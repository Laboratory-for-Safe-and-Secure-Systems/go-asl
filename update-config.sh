#!/bin/env bash

# Check if the script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Please source this script to apply the environment changes to your current shell:"
    echo "source $0 /path/to/libs-created"
    return 1 2>/dev/null || { echo "This script must be sourced, exiting."; exit 1; }
fi

# Ensure a path is provided
if [ -z "$1" ]; then
    echo "Usage: source $0 /path/to/libs-created"
    return 1
fi

# Get the path from the user input and convert to absolute path
LIBS_PATH="$1"

# Convert relative path to absolute path
if [[ ! "$LIBS_PATH" = /* ]]; then
    LIBS_PATH="$(cd "$LIBS_PATH" && pwd)"
fi

# Validate the provided path
if [ ! -d "$LIBS_PATH/lib/pkgconfig" ]; then
    echo "The provided path does not seem to have the expected structure (/lib/pkgconfig)"
    return 1
fi

# Check for sudo permissions for chown and ldconfig
if ! sudo -v >/dev/null 2>&1; then
    echo "You need sudo privileges to run this script."
    return 1
fi

# Chown the directory to the current user
sudo chown -R "$USER" "$LIBS_PATH"

# Update the pkg-config files
echo "Updating pkg-config files in $LIBS_PATH/lib/pkgconfig..."

for pc_file in "$LIBS_PATH/lib/pkgconfig"/*.pc; do
    echo "Updating $pc_file..."
    
    # Update the prefix paths in the pkg-config file
    sed -i "s|prefix=/usr/local|prefix=$LIBS_PATH|g" "$pc_file"
    sed -i "s|/usr/local|$LIBS_PATH|g" "$pc_file"
done

echo "pkg-config files updated."

# Export PKG_CONFIG_PATH to include the new path
export PKG_CONFIG_PATH="$LIBS_PATH/lib/pkgconfig:$PKG_CONFIG_PATH"
echo "PKG_CONFIG_PATH updated: $PKG_CONFIG_PATH"

# Export LD_LIBRARY_PATH and run ldconfig
export LD_LIBRARY_PATH="$LIBS_PATH/lib:$LD_LIBRARY_PATH"
echo "LD_LIBRARY_PATH updated: $LD_LIBRARY_PATH"

# Update dynamic linker run-time bindings
sudo ldconfig "$LIBS_PATH/lib"

echo "Library paths updated and ldconfig run."

# Optional: Add these exports to the user's shell profile to make it permanent
echo "Do you want to add these to your shell profile (e.g., ~/.bashrc)? (y/n): "
read -r add_to_profile
if [[ "$add_to_profile" =~ ^[Yy]$ ]]; then
    echo "export PKG_CONFIG_PATH=\"$LIBS_PATH/lib/pkgconfig:\$PKG_CONFIG_PATH\"" >> ~/.bashrc
    echo "export LD_LIBRARY_PATH=\"$LIBS_PATH/lib:\$LD_LIBRARY_PATH\"" >> ~/.bashrc
    echo "Paths added to ~/.bashrc. Run 'source ~/.bashrc' to apply them to the current session."
else
    echo "You can manually add the following to your shell profile:"
    echo "export PKG_CONFIG_PATH=\"$LIBS_PATH/lib/pkgconfig:\$PKG_CONFIG_PATH\""
    echo "export LD_LIBRARY_PATH=\"$LIBS_PATH/lib:\$LD_LIBRARY_PATH\""
fi

echo "Done."
