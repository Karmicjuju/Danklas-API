# Claude Code Audio Hooks

This project is configured with custom audio feedback for Claude Code interactions.

## Sounds

- **Success Sound** (`.claude/sounds/success.aiff`): Plays when Claude completes a task
- **Bonk Sound** (`.claude/sounds/bonk.aiff`): Plays when Claude is waiting for user input

## Configuration

The audio hooks are configured in `.claude/settings.json`:

- `hooks.on_task_complete`: Triggered when Claude finishes a task
- `hooks.on_input_request`: Triggered when Claude needs user input
- `audio.enabled`: Master toggle for all audio feedback

## Customization

### Replace Sound Files
```bash
# Replace with your own sounds
cp /path/to/your/success-sound.aiff .claude/sounds/success.aiff
cp /path/to/your/bonk-sound.aiff .claude/sounds/bonk.aiff
```

### Modify Hook Scripts
Edit `.claude/hooks/on_complete.sh` and `.claude/hooks/on_input_request.sh` to customize behavior.

### Disable Audio
Set `"enabled": false` in the hooks section of `.claude/settings.json`.

## Testing

Test the sounds manually:
```bash
.claude/hooks/on_complete.sh    # Test success sound
.claude/hooks/on_input_request.sh  # Test bonk sound
```
