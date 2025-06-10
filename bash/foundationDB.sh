#!/usr/bin/env bash

FDB_VERSION="7.3.63"
FDB_BASE_URL="https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}"
ARCH=$(uname -m)

is_command_exists() {
    command -v "$1" &> /dev/null
    return $?
}


install_fdb_macos() {
    # Determine the package names based on the architecture
    if ! [[ "$ARCH" == "arm64" ]]; then
        echo -e "Unsupported architecture: $ARCH for FoundationDB, only arm64 is supported."
        exit 1
    fi

    # Download FoundationDB package
    FDB_PACKAGE="FoundationDB-${FDB_VERSION}_arm64.pkg"
    echo "Downloading FoundationDB arm64 package for OSX..."
    curl -LO $FDB_BASE_URL/$FDB_PACKAGE

    # Install FoundationDB package
    echo "Installing FoundationDB package..."
    sudo installer -pkg $FDB_PACKAGE -target /

    # Clean up downloaded package
    echo "Cleaning up..."
    sudo rm $FDB_PACKAGE

    # Verify installation
    echo "Verifying FoundationDB installation..."
    if fdbcli --version | grep -q ${FDB_VERSION}; then
        echo -e "FoundationDB ${FDB_VERSION} installed successfully!"
    else
        echo -e "Unsupported architecture: $ARCH for FoundationDB, only arm64 is supported."
        exit 1
    fi
}

install_fdb_linux() {
    # Determine the package names based on architecture
    if [[ "$ARCH" == "x86_64" ]]; then
        FDB_PACKAGE="foundationdb-clients_${FDB_VERSION}-1_amd64.deb"
        FDB_SERVER_PACKAGE="foundationdb-server_${FDB_VERSION}-1_amd64.deb"
    elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
        FDB_PACKAGE="FoundationDB-${FDB_VERSION}_arm64.pkg"
    else
        echo "Unsupported architecture: $ARCH for FoundationDB. Supported architectures: amd64, arm64."
        exit 1
    fi

    # Update the package list
    echo "Updating package list..."

    if [[ "$ARCH" == "x86_64" ]]; then
        # Install dependencies
        echo "Installing dependencies..."
        sudo apt install -y curl gdebi-core liblzma5

        # Download FoundationDB packages
        echo "Downloading FoundationDB client from $FDB_BASE_URL/$FDB_PACKAGE"
        curl -LO $FDB_BASE_URL/$FDB_PACKAGE
        echo "Downloading FoundationDB server from $FDB_BASE_URL/$FDB_SERVER_PACKAGE"
        curl -LO $FDB_BASE_URL/$FDB_SERVER_PACKAGE

        # Install FoundationDB packages
        echo "Installing FoundationDB packages..."
        sudo gdebi -n ${FDB_PACKAGE}
        sudo gdebi -n ${FDB_SERVER_PACKAGE}

        # Clean up downloaded packages
        echo "Cleaning up..."
        sudo rm ${FDB_PACKAGE} ${FDB_SERVER_PACKAGE}
    else
        # Install dependencies
        echo "Installing dependencies..."
        sudo apt install -y curl p7zip-full cpio

        # Download FoundationDB pkg for arm64
        echo "Downloading FoundationDB package from $FDB_BASE_URL/$FDB_PACKAGE"
        curl -LO $FDB_BASE_URL/$FDB_PACKAGE

        # Extract the .pkg file
        echo "Extracting FoundationDB package..."
        mkdir -p fdb_pkg
        7z x ./FoundationDB-${FDB_VERSION}_arm64.pkg -o./fdb_pkg -y

        # Unpack FoundationDB-clients.pkg
        echo "Extracting FoundationDB-clients.pkg..."
        mkdir -p fdb_clients
        7z x ./fdb_pkg/FoundationDB-clients.pkg -o./fdb_clients -y || true

        # Unpack FoundationDB-server.pkg
        echo "Extracting FoundationDB-server.pkg..."
        mkdir -p fdb_server
        7z x ./fdb_pkg/FoundationDB-server.pkg -o./fdb_server -y || true

        # Extract payloads
        echo "Extracting payload contents for clients..."
        mkdir -p fdb_clients_payload
        cat fdb_clients/Payload~ | cpio -idmv -D fdb_clients_payload

        echo "Extracting payload contents for server..."
        mkdir -p fdb_server_payload
        cat fdb_server/Payload~ | cpio -idmv -D fdb_server_payload

        # Install FoundationDB binaries and libraries
        echo "Installing FoundationDB binaries and libraries..."
        sudo cp -f fdb_clients_payload/usr/local/bin/fdbcli /usr/local/bin/
        sudo cp -f fdb_server_payload/usr/local/bin/fdbserver /usr/local/bin/
        sudo cp -rf fdb_clients_payload/usr/local/lib/* /usr/lib/
        sudo cp -rf fdb_server_payload/usr/local/lib/* /usr/lib/
        sudo cp -rf fdb_server_payload/usr/local/etc/foundationdb /etc/

        # Ensure proper permissions
        sudo chmod +x /usr/local/bin/fdbcli /usr/local/bin/fdbserver
        sudo rm -rf fdb_pkg FoundationDB-${FDB_VERSION}_arm64.pkg
    fi

    # Configure and start FoundationDB
    echo "Configuring FoundationDB..."
    sudo systemctl enable foundationdb
    sudo systemctl start foundationdb

    # Verify installation
    echo "Verifying FoundationDB installation..."
    if fdbcli --version | grep -q ${FDB_VERSION}; then
        echo -e "FoundationDB ${FDB_VERSION} installed successfully!"
    else
        echo -e "FoundationDB installation failed."
        exit 1
    fi
}

# Detect platform and act accordingly
PLATFORM="$(uname -s)"
case $PLATFORM in
    Darwin*)
        if is_command_exists fdbcli; then
            echo "FoundationDB is already installed."
        else
            echo "FoundationDB is not installed. Setting it up for macOS..."
            install_fdb_macos
        fi
        ;;
    Linux*)
        if is_command_exists fdbcli; then
            echo "FoundationDB is already installed."
        else
            echo "FoundationDB is not installed. Setting it up for Linux..."
            install_fdb_linux
        fi
        ;;
    *)
        echo "Error: Unsupported platform: $PLATFORM. Only macOS and Linux are supported."
        exit 1
        ;;
esac