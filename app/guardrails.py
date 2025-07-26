"""Guardrails management for Danklas API with SSM Parameter Store integration."""

import os
import json
import hashlib
import logging
from typing import Dict, Any, Optional
from functools import lru_cache
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Guardrails configuration
SSM_PARAMETER_PREFIX = "/dank/guardrail"
GUARDRAIL_VERSION = "v1"
DEFAULT_GUARDRAIL_PATH = f"{SSM_PARAMETER_PREFIX}/{GUARDRAIL_VERSION}"
CACHE_TTL_SECONDS = 300  # 5 minutes

# Default guardrail configuration (fallback)
DEFAULT_GUARDRAIL = {
    "version": "1.0",
    "description": "Default Danklas API guardrail configuration",
    "content_filters": {
        "hate_speech": {"enabled": True, "threshold": 0.7},
        "inappropriate_content": {"enabled": True, "threshold": 0.8},
        "violence": {"enabled": True, "threshold": 0.6},
        "self_harm": {"enabled": True, "threshold": 0.9}
    },
    "output_filters": {
        "pii_detection": {"enabled": True, "types": ["email", "phone", "ssn", "credit_card"]},
        "profanity_filter": {"enabled": True, "level": "strict"},
        "response_length_limit": {"enabled": True, "max_tokens": 4096}
    },
    "query_filters": {
        "injection_detection": {"enabled": True},
        "malicious_intent": {"enabled": True, "threshold": 0.8},
        "query_length_limit": {"enabled": True, "max_chars": 8192}
    },
    "bedrock_config": {
        "model_settings": {
            "temperature": 0.1,
            "top_p": 0.9,
            "max_tokens": 2048
        },
        "retrieval_config": {
            "number_of_results": 5,
            "search_type": "HYBRID"
        }
    }
}

class GuardrailManager:
    """Manages guardrail configurations from SSM Parameter Store."""
    
    def __init__(self):
        self.ssm_client = None
        self._cached_guardrail = None
        self._cached_checksum = None
        self._cache_timestamp = 0
        self._initialize_ssm_client()
    
    def _initialize_ssm_client(self):
        """Initialize SSM client with proper error handling."""
        try:
            self.ssm_client = boto3.client('ssm')
            # Test connection
            self.ssm_client.describe_parameters(MaxResults=1)
            logger.info("SSM client initialized successfully")
        except NoCredentialsError:
            logger.warning("AWS credentials not found, using default guardrail")
            self.ssm_client = None
        except Exception as e:
            logger.warning(f"Failed to initialize SSM client: {e}, using default guardrail")
            self.ssm_client = None
    
    def _calculate_checksum(self, guardrail_data: Dict[str, Any]) -> str:
        """Calculate SHA256 checksum of guardrail data."""
        guardrail_json = json.dumps(guardrail_data, sort_keys=True)
        return hashlib.sha256(guardrail_json.encode()).hexdigest()
    
    def _load_from_ssm(self, parameter_path: str) -> Optional[Dict[str, Any]]:
        """Load guardrail configuration from SSM Parameter Store."""
        if not self.ssm_client:
            return None
        
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_path,
                WithDecryption=True
            )
            
            guardrail_data = json.loads(response['Parameter']['Value'])
            checksum = self._calculate_checksum(guardrail_data)
            
            logger.info(f"Loaded guardrail from SSM parameter: {parameter_path}")
            logger.info(f"Guardrail checksum: {checksum}")
            
            return guardrail_data
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ParameterNotFound':
                logger.warning(f"SSM parameter not found: {parameter_path}")
            else:
                logger.error(f"Failed to load guardrail from SSM: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in SSM parameter {parameter_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error loading guardrail from SSM: {e}")
            return None
    
    def _is_cache_valid(self) -> bool:
        """Check if cached guardrail is still valid."""
        import time
        return (time.time() - self._cache_timestamp) < CACHE_TTL_SECONDS
    
    def get_guardrail(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get current guardrail configuration.
        
        Args:
            force_refresh: Force refresh from SSM Parameter Store
            
        Returns:
            Dictionary containing guardrail configuration
        """
        # Return cached version if valid and not forcing refresh
        if not force_refresh and self._cached_guardrail and self._is_cache_valid():
            return self._cached_guardrail
        
        # Try to load from SSM
        guardrail = self._load_from_ssm(DEFAULT_GUARDRAIL_PATH)
        
        if guardrail:
            # Cache the loaded guardrail
            import time
            self._cached_guardrail = guardrail
            self._cached_checksum = self._calculate_checksum(guardrail)
            self._cache_timestamp = time.time()
            
            logger.info(f"Guardrail loaded and cached with checksum: {self._cached_checksum}")
            return guardrail
        else:
            # Fallback to default guardrail
            logger.info("Using default guardrail configuration")
            default_checksum = self._calculate_checksum(DEFAULT_GUARDRAIL)
            logger.info(f"Default guardrail checksum: {default_checksum}")
            return DEFAULT_GUARDRAIL
    
    def get_guardrail_checksum(self) -> str:
        """Get the checksum of the current guardrail configuration."""
        if self._cached_checksum and self._is_cache_valid():
            return self._cached_checksum
        
        # Force refresh to get current checksum
        self.get_guardrail(force_refresh=True)
        return self._cached_checksum or self._calculate_checksum(DEFAULT_GUARDRAIL)
    
    def validate_guardrail(self, guardrail_data: Dict[str, Any]) -> bool:
        """
        Validate guardrail configuration structure.
        
        Args:
            guardrail_data: Guardrail configuration to validate
            
        Returns:
            True if valid, False otherwise
        """
        required_sections = ["content_filters", "output_filters", "query_filters", "bedrock_config"]
        
        try:
            for section in required_sections:
                if section not in guardrail_data:
                    logger.error(f"Missing required section: {section}")
                    return False
            
            # Validate content filters
            content_filters = guardrail_data["content_filters"]
            for filter_name, config in content_filters.items():
                if not isinstance(config, dict) or "enabled" not in config:
                    logger.error(f"Invalid content filter configuration: {filter_name}")
                    return False
            
            # Validate bedrock config
            bedrock_config = guardrail_data["bedrock_config"]
            if "model_settings" not in bedrock_config or "retrieval_config" not in bedrock_config:
                logger.error("Invalid bedrock configuration")
                return False
            
            logger.info("Guardrail configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Guardrail validation error: {e}")
            return False

# Global guardrail manager instance
_guardrail_manager = None

def get_guardrail_manager() -> GuardrailManager:
    """Get global guardrail manager instance."""
    global _guardrail_manager
    if _guardrail_manager is None:
        _guardrail_manager = GuardrailManager()
    return _guardrail_manager

def get_current_guardrail() -> Dict[str, Any]:
    """Get current guardrail configuration."""
    manager = get_guardrail_manager()
    return manager.get_guardrail()

def get_guardrail_info() -> Dict[str, str]:
    """Get guardrail metadata information."""
    manager = get_guardrail_manager()
    guardrail = manager.get_guardrail()
    checksum = manager.get_guardrail_checksum()
    
    return {
        "version": guardrail.get("version", "unknown"),
        "description": guardrail.get("description", ""),
        "checksum": checksum,
        "parameter_path": DEFAULT_GUARDRAIL_PATH
    } 