# ActiveMQ Pluggable Authentication Framework
This project provides a flexible authentication framework for Apache ActiveMQ Classic, enabling secure, extensible authentication across various mechanisms.

## 🔐 Supported Authentication Modules
✅ IP-based Authentication: Trust or reject clients based on source IPs.

✅ Client SSL Certificate (mTLS): Authenticate clients using X.509 certificates.

✅ JWT Authentication with JWKS: Support for multiple Identity Providers, auto JWKS URI discovery via OpenID Connect.

🔁 Pluggable Pipelines: Compose multiple authentication methods per connector using configurable pipelines.

## ⚙️ Configuration Guide
### Step 1: Copy Libraries
Copy the following JARs to ${ACTIVEMQ_BASE}/lib/optional:

      episteme-auth-classic-1.0.0.jar  
      episteme-auth-core-1.0.0.jar  
      java-jwt-4.5.0.jar  
      jwks-rsa-0.22.1.jar  

### Step 2: Update activemq.xml
Add the custom authentication plugin to your broker configuration inside broker element:
```
  <plugins>  
      <bean class="com.activemq.auth.classic.CompositeAuthPlugin"/>  
  </plugins>
```
### Step 3: Create auth-config.json
Place this file inside ${ACTIVEMQ_BASE}/conf/. Here’s a sample:  
```
{
  "ipAcl": {
    "allow": [
      "192.168.1.0/24",
      "10.0.0.5/32",
      "172.16.0.0/12",
      "127.0.0.1",
      "[0:0:0:0:0:0:0:1]"
    ]
  },
  "cert": {
    "allowedThumbprints": [
      "96f168ed9521921fb56XXXX070aa82ef3f8b32c0",
      "7a9cd4fafYYYYad50fe49de2963ca763a911024d"
    ]
  },
  "pipelines": {
    "ws": [
      "ip-acl-validator"
    ],
    "ssl": [
      "ip-acl-validator",
      "client-cert-validator"
    ],
    "openwire": [
      "ip-acl-validator",
      "jwt-validator"
    ]
  },
  "jwt": {
    "idps": {
      "entra": {
        "issuer": "https://login.microsoftonline.com/e9d1afc4-345555-4e39-beb3-1ea201a534df/v2.0",
        "audience": [
          "7c256992-af92-4231-234556-6505f139693a"
        ]
      }
    }
  }
}
```
🔁 Pipelines run in the order listed per connector. Validation short-circuits on first success.

## 📁 Project Modules
auth-core: Shared authentication logic and interfaces.

auth-classic: ActiveMQ Classic integration.

auth-artemis (planned): ActiveMQ Artemis integration (WIP).

## 📜 License
Apache 2.0 License
