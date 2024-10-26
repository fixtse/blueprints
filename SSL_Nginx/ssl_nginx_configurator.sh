#!/bin/bash

# Function to display help message
show_help() {
  echo "Usage: $0 <domain> <ip:port> | setup"
  echo
  echo "This script generates an SSL certificate and key for the specified domain and also creates the Nginx reverse-proxy configuration file."
  echo "It also has a setup option to create a default nginx.conf and docker-compose.yml."
  echo
  echo "Arguments:"
  echo "  <domain>    The domain name for which to generate the SSL certificate and key."
  echo "  <ip:port>   The IP address and port to be used in the Nginx configuration."
  echo "  setup       Run the setup to create nginx.conf and docker-compose.yml."
  echo
  echo "If a domain (e.g., example.com) is provided, a wildcard certificate will be generated,"
  echo "which can be used for any subdomain (e.g., *.example.com)."
  echo "If a subdomain (e.g., sub.example.com) is provided, only that specific subdomain will be included."
  echo
  echo "Example:"
  echo "  $0 example.com 192.168.1.1:8080"
  echo "  $0 sub.example.com 192.168.1.1:8080"
  echo "  $0 setup"
}

# Function to get the expiration date of an existing certificate
get_expiration_date() {
  openssl x509 -enddate -noout -in "$1" | cut -d= -f2 | xargs -I {} date -d {} +"%Y-%m-%d %H:%M:%S"
}

# Function to create nginx.conf
create_nginx_conf() {
mkdir -p nginx
  cat <<EOL > nginx/nginx.conf
worker_processes  auto;
pid		/var/run/nginx.pid;

events {
		worker_connections  1024;
}

http {
		##
		# Basic Settings
		##

		sendfile on;
		tcp_nopush on;
		tcp_nodelay on;
		keepalive_timeout 65;
		types_hash_max_size 2048;
    server_tokens off;
		
		
		default_type  application/octet-stream;

		##
		# SSL Settings
		##

		ssl_protocols TLSv1.2 TLSv1.3;
		ssl_prefer_server_ciphers on;
		
		
		##
    # Logging Settings
    ##

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
		
		gzip on;
		gzip_disable "msie6";
		gzip_vary on;
		gzip_proxied any;
		gzip_comp_level 6;
		gzip_buffers 16 8k;
		gzip_http_version 1.1;
		gzip_min_length 256;
		gzip_types
		application/atom+xml
		application/geo+json
		application/javascript
		application/x-javascript
		application/json
		application/ld+json
		application/manifest+json
		application/rdf+xml
		application/rss+xml
		application/xhtml+xml
		application/xml
		font/eot
		font/otf
		font/ttf
		image/svg+xml
		text/css
		text/javascript
		text/plain
		text/xml;

		include /etc/nginx/conf.d/*.conf;
}
EOL
}

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
  echo "openssl is not installed. Attempting to install it..."
  sudo apt install -y openssl
  if [ $? -ne 0 ]; then
    echo "Failed to install openssl. Please install it manually and rerun the script."
    exit 1
  fi
fi

# Check if setup option is provided
if [ "$1" == "setup" ]; then
  if [ -f "nginx/nginx.conf" ]; then
    read -p "nginx.conf already exists. Do you want to overwrite it? (y/n): " OVERWRITE_NGINX
    if [ "$OVERWRITE_NGINX" == "y" ]; then
      create_nginx_conf
      echo "nginx.conf has been created."
    else
      echo "nginx.conf has not been overwritten."
    fi
  else
    create_nginx_conf
    echo "nginx.conf has been created."
  fi

  echo "Choose your setup option:"
  echo "1) AdGuard Home + Nginx"
  echo "2) Just Nginx"
  read -p "Enter your choice (1 or 2): " SETUP_CHOICE

  if [ "$SETUP_CHOICE" == "1" ]; then
    FILE_CONTENT='services:
  nginx:
    container_name: SSL-NGINX
    image: chainguard/nginx:latest
    ports:
      - "443:8558"
      - "80:8557"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/certs:/etc/nginx/certs
      - ./nginx/logs:/home/nginx/logs
    restart: always
    
  adguard_home:
    container_name: Adguard-Home
    image: fixtse/adguard-home-wolfi:latest
    ports:
      - "3000:80"
      - "53:53/tcp"
      - "53:53/udp"
    volumes:
      - ./adguard/conf:/opt/AdGuardHome/conf
      - ./adguard/work:/opt/AdGuardHome/work
    restart: always'
  elif [ "$SETUP_CHOICE" == "2" ]; then
    FILE_CONTENT='services:
  nginx:
    container_name: SSL-NGINX
    image: chainguard/nginx:latest
    ports:
      - "443:8558"
      - "80:8557"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./nginx/certs:/etc/nginx/certs
      - ./nginx/logs:/home/nginx/logs
    restart: always'
  else
    echo "Invalid choice. Exiting setup."
    exit 1
  fi

  echo "$FILE_CONTENT" > docker-compose.yml
  echo "docker-compose.yml created. Now run the script again to create your first custom domain"
  echo "$0 <domain> <ip:port>"
  exit 0
fi

# Check if domain and IP arguments are provided
if [ -z "$1" ] || [ -z "$2" ]; then
  show_help
  exit 1
fi

DOMAIN=$1
IP=$2
CERT_DIR="nginx/certs"
CERT_FILE="${CERT_DIR}/${DOMAIN}.crt"
KEY_FILE="${CERT_DIR}/${DOMAIN}.key"
NGINX_CONF_DIR="nginx/conf.d"
NGINX_CONF_FILE="${NGINX_CONF_DIR}/${DOMAIN}.conf"
NGINX_LOGS_DIR="nginx/logs"

# Create the certs, conf.d and logs directories if they don't exist
mkdir -p "$CERT_DIR"
mkdir -p "$NGINX_CONF_DIR"
mkdir -p "$NGINX_LOGS_DIR"

# Check if the certificate file already exists
if [ -f "$CERT_FILE" ]; then
  EXPIRATION_DATE=$(get_expiration_date "$CERT_FILE")
  echo "A certificate for ${DOMAIN} already exists and is valid until ${EXPIRATION_DATE}."
  read -p "Do you want to overwrite it? (y/n): " OVERWRITE
  if [ "$OVERWRITE" != "y" ]; then
    echo "Operation cancelled. The existing certificate has not been overwritten."
    exit 0
  fi
fi

# Check if the domain is a subdomain
if [[ "$DOMAIN" == *.*.* ]]; then
  ALT_NAME="DNS:${DOMAIN}"
else
  ALT_NAME="DNS:${DOMAIN},DNS:*.${DOMAIN}"
fi

# Generate the SSL certificate and key
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$KEY_FILE" -out "$CERT_FILE" \
  -subj "/CN=${DOMAIN}" \
  -addext "subjectAltName=${ALT_NAME}"
  

# Create Empty Access and Error Log Files
touch ${NGINX_LOGS_DIR}/${DOMAIN}.error
touch ${NGINX_LOGS_DIR}/${DOMAIN}.access

# Set permissions for the files
chmod 644 "$CERT_FILE" "$KEY_FILE" 
chmod 666 "${NGINX_LOGS_DIR}/${DOMAIN}.access" "${NGINX_LOGS_DIR}/${DOMAIN}.error"

# Get the expiration date of the new certificate
NEW_EXPIRATION_DATE=$(get_expiration_date "$CERT_FILE")

echo "SSL certificate and key have been generated for ${DOMAIN}"
echo "The new certificate is valid until ${NEW_EXPIRATION_DATE}"

# Create the Nginx configuration file
cat <<EOL > "$NGINX_CONF_FILE"

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
  listen 8557;
  server_name ${DOMAIN};
  return 301 https://\$host\$request_uri;
}

server {
  listen 8558 ssl;
  server_name ${DOMAIN};
  http2  on;
  ssl_certificate     /etc/nginx/certs/${DOMAIN}.crt;
  ssl_certificate_key /etc/nginx/certs/${DOMAIN}.key;

  client_max_body_size 4G;
  ssl_ciphers ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-CCM:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-CCM:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256;
  ssl_session_cache  builtin:1000  shared:SSL:10m;
  ssl_prefer_server_ciphers on;
  add_header Strict-Transport-Security "max-age=31536000; includeSubdomains";
  
  access_log /home/nginx/logs/${DOMAIN}.access;
  error_log /home/nginx/logs/${DOMAIN}.error;

  location / {
    proxy_pass http://${IP}/;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_redirect http:// https://;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
    proxy_set_header Host \$host;
    proxy_set_header Scheme \$scheme;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Host \$http_host;
    proxy_buffering off;
  }
}
EOL

echo "Nginx configuration file has been created for ${DOMAIN} at ${NGINX_CONF_FILE}"

# Check if the Docker container SSL-NGINX is running
if docker compose ps | grep -q 'SSL-NGINX'; then
  echo "Restarting the SSL-NGINX container..."
  docker compose restart nginx
  echo "You can use this link to go to your application: https://${DOMAIN} after you set the DNS Rewrite in Adguard Home"
else
  read -p "The SSL-NGINX container is not running. Do you want to start it? (y/n): " START_CONTAINER
  if [ "$START_CONTAINER" == "y" ]; then
    docker compose up -d
	echo "You can use this link to go to your application: https://${DOMAIN} after you set the DNS Rewrite in Adguard Home"
  else
    echo "No worries! You can start the SSL-NGINX container later with the command: docker compose up -d"
  fi
fi

if docker compose ps | grep -q 'Adguard-Home'; then
  echo "You can access AdGuard Home at http://localhost:3000"
fi