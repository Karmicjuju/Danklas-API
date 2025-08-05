# AWS Verified Permissions (AVP) Integration

This document describes the AWS Verified Permissions integration in the Danklas API.

## Overview

The Danklas API now uses AWS Verified Permissions (AVP) for fine-grained authorization checks on all endpoints. This provides policy-based access control that can be managed centrally through AWS.

## Architecture

### Authorization Flow

1. **JWT Authentication**: User presents JWT token (unchanged)
2. **Token Validation**: Okta JWT is validated and claims extracted (unchanged)
3. **AVP Authorization**: For each endpoint, an authorization check is made to AVP
4. **Metadata Filtering**: If authorized, tenant-based metadata filtering is applied (unchanged)
5. **Bedrock Query**: Knowledge base query is executed with filters (unchanged)

### AVP Integration Points

The `check_avp_authorization()` function is called for each endpoint:

- **Root endpoint** (`/`): Action=`read`, Resource=`ApiInfo`
- **Health endpoint** (`/health`): Action=`read`, Resource=`HealthStatus`
- **Query endpoint** (`/knowledge-bases/{kb_id}/query`): Action=`query`, Resource=`KnowledgeBase::{kb_id}`

### AVP Request Format

```python
{
    "principal": {
        "entityType": "User",
        "entityId": "<user_sub_from_jwt>"
    },
    "action": {
        "actionType": "DanklasAPI::Action",
        "actionId": "<action_name>"
    },
    "resource": {
        "entityType": "DanklasAPI::Resource",
        "entityId": "<resource_identifier>"
    },
    "context": {
        "contextMap": {
            "tenant_id": {"string": "<tenant_id>"},
            "roles": {"list": [{"string": "role1"}, {"string": "role2"}]},
            "department": {"string": "<department>"}  # optional
        }
    }
}
```

## Configuration

### Environment Variables

- `AVP_POLICY_STORE_ID`: The AWS Verified Permissions policy store ID
- `AWS_REGION`: AWS region for AVP client (same as Bedrock)

### Required AWS Permissions

The API's IAM role/user needs the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "verifiedpermissions:IsAuthorized"
            ],
            "Resource": "arn:aws:verifiedpermissions:*:*:policy-store/*"
        }
    ]
}
```

## Cedar Policy Examples

Here are example Cedar policies that would work with this integration:

### Allow all authenticated users to access health and API info
```cedar
permit(
    principal,
    action in [DanklasAPI::Action::"read"],
    resource in [DanklasAPI::Resource::"HealthStatus", DanklasAPI::Resource::"ApiInfo"]
);
```

### Allow users to query their tenant's knowledge bases
```cedar
permit(
    principal,
    action == DanklasAPI::Action::"query",
    resource
)
when {
    resource.id like "KnowledgeBase::kb-*" &&
    context.tenant_id == resource.tenant_id
};
```

### Allow admin users to query any knowledge base
```cedar
permit(
    principal,
    action == DanklasAPI::Action::"query",
    resource
)
when {
    context.roles.contains("admin")
};
```

### Department-specific access
```cedar
permit(
    principal,
    action == DanklasAPI::Action::"query",
    resource
)
when {
    resource.id like "KnowledgeBase::kb-engineering-*" &&
    context.department == "engineering"
};
```

## Testing

The integration includes comprehensive tests:

1. **Authorization Success**: Tests successful AVP allow decisions
2. **Authorization Denial**: Tests AVP deny decisions return 403
3. **Service Errors**: Tests fail-closed behavior when AVP is unavailable
4. **Context Formatting**: Tests proper formatting of AVP requests

### Test Environment

In test environment (`DANKLAS_ENV=test`), AVP checks are bypassed to allow unit testing without AWS dependencies.

## Security Considerations

1. **Fail Closed**: If AVP is unavailable or returns an error, access is denied
2. **Backward Compatibility**: Tenant-based KB access checks remain as an additional layer
3. **Context Enrichment**: JWT claims are passed to AVP for policy decisions
4. **Audit Trail**: All authorization decisions are logged

## Migration Notes

When migrating from the previous authorization model:

1. Set up AVP policy store with appropriate Cedar policies
2. Configure `AVP_POLICY_STORE_ID` environment variable
3. Ensure IAM permissions are granted
4. Test authorization decisions before removing old access controls
5. The existing tenant-based filtering (`check_kb_access`) remains as defense-in-depth

## Future Enhancements

1. **Policy Templates**: Create reusable policy templates for common access patterns
2. **Dynamic Context**: Add more context attributes (IP, time of day, etc.)
3. **Policy Caching**: Implement local policy evaluation for performance
4. **Batch Authorization**: Check multiple resources in a single AVP call