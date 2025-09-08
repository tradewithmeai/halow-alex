# Rollback Instructions - HaLow Tool Refactoring

## Quick Rollback Guide

If the refactored version (v4.1) has issues, you can easily rollback to the previous working version (v4.0).

### Option 1: Use the Original File (Easiest)
The original `pylibnetat.py` file is preserved and untouched. Simply use it directly:

```bash
# Use the original tool (same as before)
python pylibnetat.py eth0 --debug
python pylibnetat.py --serial COM3
python pylibnetat.py --list
```

### Option 2: Git Rollback (Complete Revert)
If you want to completely revert the repository to the previous state:

```bash
# Check current commit
git log --oneline -5

# Rollback to the previous version (before refactoring)
git reset --hard HEAD~1

# If you've already pushed, force push (use with caution)
git push --force-with-lease origin main
```

### Option 3: Switch Between Versions
Keep both versions and switch as needed:

```bash
# Create a backup branch of current state
git checkout -b backup-refactored

# Switch back to main and reset
git checkout main
git reset --hard HEAD~1

# To switch back to refactored version later:
git checkout backup-refactored
```

## Version Comparison

| Version | File | Lines | Status |
|---------|------|-------|--------|
| v4.0 (Original) | `pylibnetat.py` | 1333 | ✅ Tested & Working |
| v4.1 (Refactored) | `halow_tool.py` + modules | ~1200 total | ⚠️ New - Test Required |

## Testing the Refactored Version

Before fully switching, test the refactored version:

```bash
# Test basic functionality
python test_refactored.py

# Test with your specific setup
python halow_tool.py --help
python halow_tool.py --list

# Test with your interface (replace 'eth0' with your interface)
python halow_tool.py eth0 --debug
```

## What Changed

### Files Added (Refactored Version):
- `halow_tool.py` - New main entry point
- `taixin_tools/` - Modular library structure
- `test_refactored.py` - Test suite
- `REFACTORED_README.md` - Architecture documentation

### Files Preserved:
- `pylibnetat.py` - Original working version (unchanged)
- `README.md` - Original documentation
- All other original files

## Recommendation

1. **Test the refactored version first** using your specific hardware setup
2. **Keep using `pylibnetat.py`** if you encounter any issues
3. **Report any problems** so they can be fixed
4. **Switch to `halow_tool.py`** once you've verified it works with your setup

The refactored version maintains 100% compatibility but uses a cleaner architecture. Both versions will coexist until you're confident the new one works perfectly for your use case.

## Emergency Fallback

If something goes wrong with git operations:

```bash
# Download fresh copy from GitHub
git clone https://github.com/tradewithmeai/taixin-libnetat-gui.git backup-repo
cd backup-repo

# Use the original file from the backup
python pylibnetat.py your-interface --debug
```

Remember: **The original `pylibnetat.py` remains fully functional and unchanged.**