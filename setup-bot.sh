#!/bin/bash


MAIN_PY_URL="https://raw.githubusercontent.com/amir-kr/Evara_Tunnel/main/tunnel-m.py"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 


error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}


install_bot() {

    if [ "$EUID" -ne 0 ]; then
        error_exit "This script must be run with root privileges. Please use sudo."
    fi

 
    echo -e "${YELLOW}Updating packages and installing prerequisites...${NC}"
    apt update || error_exit "Failed to update packages."
    apt install -y python3 python3-pip curl || error_exit "Failed to install prerequisites (python3, pip, curl)."


    PROJECT_PATH="/opt/telegram-bot"
    echo -e "${YELLOW}Creating project directory at $PROJECT_PATH...${NC}"
    mkdir -p "$PROJECT_PATH" || error_exit "Failed to create project directory."
    cd "$PROJECT_PATH" || error_exit "Failed to enter project directory."

    
    echo -e "${YELLOW}Downloading tunnel-m.py from $MAIN_PY_URL...${NC}"
    curl -o tunnel-m.py "$MAIN_PY_URL" || error_exit "Failed to download tunnel-m.py."
    if [ ! -f "tunnel-m.py" ]; then
        error_exit "tunnel-m.py not found after download."
    fi

    
    echo -e "${YELLOW}Creating requirements.txt...${NC}"
    cat > requirements.txt << EOL
aiogram==2.25.1
paramiko==3.3.1
EOL

    
    echo -e "${YELLOW}Installing Python dependencies from requirements.txt...${NC}"
    pip3 install -r requirements.txt || error_exit "Failed to install Python dependencies."

    
    clear
    
    read -p "Telegram Bot Token: " BOT_TOKEN
    read -p "Admin Telegram User ID: " ADMIN_ID
    read -p "Admin ID User 2 (Admin ID,ID User 2): " USER_IDS

    
    if ! [[ "$ADMIN_ID" =~ ^[0-9]+$ ]]; then
        error_exit "Admin ID must be numeric."
    fi

    
    USER_IDS=$(echo "$USER_IDS" | tr -d '[:space:]') 
    if [ -z "$USER_IDS" ]; then
        error_exit "At least one user ID must be provided."
    fi
    
    USER_IDS_ARRAY=$(echo "$USER_IDS" | sed 's/,/, /g')
    
    for ID in $(echo "$USER_IDS" | tr ',' ' '); do
        if ! [[ "$ID" =~ ^[0-9]+$ ]]; then
            error_exit "All user IDs must be numeric."
        fi
    done
    
    if [[ ! "$USER_IDS" =~ (^|,)"$ADMIN_ID"(,|$) ]]; then
        error_exit "Admin ID must be included in the allowed user IDs list."
    fi

    
    echo -e "${YELLOW}Creating config.py...${NC}"
    cat > config.py << EOL
# Telegram bot token
API_TOKEN = '$BOT_TOKEN'

# Admin numeric user ID
ADMIN_ID = $ADMIN_ID

# List of allowed numeric user IDs
ALLOWED_USER_IDS = [$USER_IDS_ARRAY]
EOL

    
    echo -e "${YELLOW}Creating bot.service...${NC}"
    CURRENT_USER=$(logname 2>/dev/null || echo "$SUDO_USER")
    if [ -z "$CURRENT_USER" ]; then
        read -p "Please enter the server username: " CURRENT_USER
    fi

    cat > bot.service << EOL
[Unit]
Description=evara tunnel Bot
After=network.target

[Service]
ExecStart=/usr/bin/python3 $PROJECT_PATH/tunnel-m.py
WorkingDirectory=$PROJECT_PATH
Restart=always
User=$CURRENT_USER
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOL

    
    echo -e "${YELLOW}Copying and enabling systemd service...${NC}"
    cp bot.service /etc/systemd/system/ || error_exit "Failed to copy bot.service."
    systemctl daemon-reload || error_exit "Failed to reload systemd."
    systemctl enable bot.service || error_exit "Failed to enable bot.service."
    systemctl start bot.service || error_exit "Failed to start bot.service."

    
    echo -e "${YELLOW}Checking service status...${NC}"
    sleep 2
    if systemctl is-active --quiet bot.service; then
        echo -e "${GREEN}Bot successfully started and is running!${NC}"
        echo -e "${GREEN}Service status:${NC}"
        systemctl status bot.service --no-pager
    else
        echo -e "${RED}Error: bot.service is not running.${NC}"
        systemctl status bot.service --no-pager
        error_exit "Please check the service status."
    fi

    echo -e "${GREEN}Setup and installation completed successfully!${NC}"
    echo -e "To check the bot status in the future, use:"
    echo -e "  sudo systemctl status bot.service"
    echo -e "To stop the bot:"
    echo -e "  sudo systemctl stop bot.service"
    echo -e "To update tunnel-m.py, replace $PROJECT_PATH/tunnel-m.py and restart:"
    echo -e "  sudo systemctl restart bot.service"
}


uninstall_bot() {
    echo -e "${YELLOW}Uninstalling evara tunnel Bot...${NC}"

    
    systemctl stop bot.service 2>/dev/null
    systemctl disable bot.service 2>/dev/null
    rm -f /etc/systemd/system/bot.service
    systemctl daemon-reload

    
    PROJECT_PATH="/opt/telegram-bot"
    if [ -d "$PROJECT_PATH" ]; then
        echo -e "${YELLOW}Removing project directory $PROJECT_PATH...${NC}"
        rm -rf "$PROJECT_PATH" || error_exit "Failed to remove project directory."
    fi

    
    echo -e "${YELLOW}Removing Python dependencies...${NC}"
    pip3 uninstall -y aiogram paramiko 2>/dev/null || echo -e "${YELLOW}Note: Some dependencies might not be removed if used by other applications.${NC}"

    echo -e "${GREEN}Uninstallation completed successfully!${NC}"
}


clear
while true; do
    echo -e "${BLUE}   ___ __ __   ____  ____    ____      ______  __ __  ____   ____     ___  _     
  /  _]  |  | /    ||    \  /    |    |      ||  |  ||    \ |    \   /  _]| |    
 /  [_|  |  ||  o  ||  D  )|  o  |    |      ||  |  ||  _  ||  _  | /  [_ | |    
|    _]  |  ||     ||    / |     |    |_|  |_||  |  ||  |  ||  |  ||    _]| |___ 
|   [_|  :  ||  _  ||    \ |  _  |      |  |  |  :  ||  |  ||  |  ||   [_ |     |
|     |\   / |  |  ||  .  \|  |  |      |  |  |     ||  |  ||  |  ||     ||     |
|_____| \_/  |__|__||__|\_||__|__|      |__|   \__,_||__|__||__|__||_____||_____|
                                                                                 ${NC}"
    echo -e "${GREEN}1) Install${NC}"
    echo "2) Uninstall"
    echo "3) Exit"
    read -p "Please select an option [1-3]: " choice

    case $choice in
        1)
            install_bot
            break
            ;;
        2)
            uninstall_bot
            break
            ;;
        3)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please select 1, 2, or 3.${NC}"
            ;;
    esac
done
