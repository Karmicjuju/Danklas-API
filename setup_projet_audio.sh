#!/bin/bash

# Claude Code Project Audio Hooks Setup
# This script configures audio hooks in your project's .claude/settings.json

echo "Setting up Claude Code audio hooks for this project..."

# Create .claude directory if it doesn't exist
mkdir -p .claude

# Create sounds directory within the project
mkdir -p .claude/sounds

echo "Creating sound files..."

# Create success sound (pleasant chime)
say -v "Bells" -r 200 "success" -o .claude/sounds/success.aiff 2>/dev/null || 
cp /System/Library/Sounds/Glass.aiff .claude/sounds/success.aiff 2>/dev/null ||
echo "Warning: Could not create success.aiff"

# Create bonk sound (playful bonk)
say -v "Bad News" -r 150 "bonk" -o .claude/sounds/bonk.aiff 2>/dev/null ||
cp /System/Library/Sounds/Sosumi.aiff .claude/sounds/bonk.aiff 2>/dev/null ||
echo "Warning: Could not create bonk.aiff"

# Create hook scripts
cat > .claude/hooks/on_complete.sh << 'EOF'
#!/bin/bash
# Plays when Claude completes a task
if [[ -f ".claude/sounds/success.aiff" ]]; then
    afplay .claude/sounds/success.aiff &
else
    osascript -e 'display notification "Task completed!" with title "Claude Code"' -e 'beep 1'
fi
EOF

mkdir -p .claude/hooks
cat > .claude/hooks/on_input_request.sh << 'EOF'
#!/bin/bash
# Plays when Claude is waiting for user input
if [[ -f ".claude/sounds/bonk.aiff" ]]; then
    afplay .claude/sounds/bonk.aiff &
else
    osascript -e 'beep 2'
fi
EOF

# Make hook scripts executable
chmod +x .claude/hooks/on_complete.sh
chmod +x .claude/hooks/on_input_request.sh

# Create or update settings.json
echo "Configuring .claude/settings.json..."

# Check if settings.json exists and backup if it does
if [[ -f ".claude/settings.json" ]]; then
    cp .claude/settings.json .claude/settings.json.backup
    echo "Backed up existing settings.json"
fi

# Create new settings.json with audio hooks configuration
cat > .claude/settings.json << 'EOF'
{
  "project_name": "Project with Audio Hooks",
  "hooks": {
    "on_task_complete": {
      "enabled": true,
      "command": ".claude/hooks/on_complete.sh",
      "description": "Play success sound when task completes"
    },
    "on_input_request": {
      "enabled": true,
      "command": ".claude/hooks/on_input_request.sh",
      "description": "Play bonk sound when waiting for input"
    },
    "on_error": {
      "enabled": false,
      "command": "osascript -e 'beep 3'",
      "description": "Play error sound on failures"
    }
  },
  "audio": {
    "enabled": true,
    "success_sound": ".claude/sounds/success.aiff",
    "input_sound": ".claude/sounds/bonk.aiff",
    "volume": 0.7
  },
  "notifications": {
    "show_completion": true,
    "show_errors": true,
    "sound_enabled": true
  }
}
EOF

# Create a README for the audio setup
cat > .claude/AUDIO_SETUP.md << 'EOF'
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
EOF

echo ""
echo "✓ Audio hooks configured for this project!"
echo ""
echo "Files created:"
echo "  📁 .claude/settings.json     - Main configuration"
echo "  📁 .claude/sounds/           - Audio files directory"
echo "  📁 .claude/hooks/            - Hook scripts"
echo "  📄 .claude/AUDIO_SETUP.md    - Documentation"
echo ""
echo "🎵 Success sound: .claude/sounds/success.aiff"
echo "🔊 Bonk sound: .claude/sounds/bonk.aiff"
echo ""
echo "Now when you run 'claude' in this directory:"
echo "  • Task completions will play the success sound"
echo "  • Input requests will play the bonk sound"
echo ""
echo "To customize sounds, replace the .aiff files in .claude/sounds/"
echo "To disable, edit .claude/settings.json and set 'enabled': false"

# Test if Claude Code recognizes the configuration
if command -v claude >/dev/null 2>&1; then
    echo ""
    echo "Testing configuration..."
    echo "Run 'claude --help' to see if hooks are loaded"
else
    echo ""
    echo "Note: Install Claude Code to use these hooks"
    echo "The configuration is ready when you install it!"
fi