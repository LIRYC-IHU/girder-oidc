# Girder OIDC - Development Deployment

A complete Girder deployment with OIDC/Keycloak authentication, using Docker Compose with TLS support for secure local development.

## Services

The `docker-compose.yml` orchestrates three services:

| Service | Container | Port | Purpose |
|---------|-----------|------|---------|
| **Girder** | girder-kitware | 8080 | Main application server |
| **Keycloak** | girder-keycloak | 8443 | OIDC identity provider |
| **MongoDB** | girder-mongo | 27017 | Data persistence |

## TLS Certificate Setup

The deployment uses HTTPS with TLS certificates for secure communication between services. Certificates must be generated before starting the Docker stack.

### Generate Self-Signed Certificates (Development)

Using **mkcert** (recommended for development):

```bash
# Install mkcert (macOS)
brew install mkcert

# Create a local CA and trust it
mkcert -install

# Generate certificates for localhost
mkcert -cert-file cert.pem -key-file key.pem localhost "*.localhost" 127.0.0.1 ::1

# Create directory and set environment variable
mkdir -p ~/certs
mv cert.pem key.pem rootCA.pem ~/certs/
export TLS_CERT=~/certs
```

### Alternative: Using OpenSSL

```bash
# Generate self-signed certificate (90 days)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 90 -nodes \
  -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"

# Create directory and set environment variable
mkdir -p ~/certs
mv cert.pem key.pem ~/certs/
export TLS_CERT=~/certs

# Extract root CA (for client verification)
cp cert.pem ~/certs/rootCA.pem
```

## Deployment

### 1. Set Environment Variable

```bash
export TLS_CERT=~/certs  # or wherever you stored certificates
```

### 2. Start Services

```bash
docker compose up -d
```

### 3. Monitor Startup

```bash
docker compose logs -f
```

Expected output:
- Girder: "Bus STARTED"
- MongoDB: "Waiting for connections"
- Keycloak: "Listening on" message

### 4. Create the keycloak realms & client
```bash
setup_keycloak.sh
```

### 5. Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Girder** | http://localhost:8080 | Create on first visit |
| **Keycloak Admin** | https://localhost:8443/admin | admin / admin |

## Configuration

After services are running:

1. **Create Girder admin account** at http://localhost:8080
2. **Configure OIDC in Girder Admin Panel**:
   - Keycloak URL: `https://keycloak:8443`
   - Realm: `girder`
   - Client ID: `girder`
   - Client Secret: (from Keycloak - you can access it from the Keycloak admin page)
3. **Test OIDC login** via the Keycloak button on login page

## Stopping Services

```bash
# Stop containers (keep volumes)
docker compose down

# Stop and remove all data
docker compose down -v
```

## Troubleshooting

**Certificates not found:**
```bash
# Verify TLS_CERT is set
echo $TLS_CERT

# Verify files exist
ls -la $TLS_CERT/{cert.pem,key.pem,rootCA.pem}
```

**Keycloak HTTPS errors:**
- Ensure `KC_HTTPS_CERTIFICATE_FILE` and `KC_HTTPS_CERTIFICATE_KEY_FILE` paths match mounted volumes
- Check certificate validity: `openssl x509 -in cert.pem -text -noout`

**Browser SSL warnings (self-signed certs):**
- Expected for development; browser allows proceeding after warning
- For smooth experience, import `rootCA.pem` into system keychain (macOS: `Keychain Access → Certificate Assistant → Import`)
