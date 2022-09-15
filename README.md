# EthrRevocationRegistry Veramo Plugin
A [`CredentialStatusPlugin`](https://github.com/uport-project/veramo/tree/next/packages/credential-status) plugin for the Veramo agent enabling it to resolve the status of a Verifiable Credential using the `EthrRevocationRegistry` revocation method. It leverages [`@spherity/ethr-revocation-registry-controller`](https://github.com/spherity/ethr-revocation-registry-controller) to interact with an [EIP-5539](https://github.com/ethereum/EIPs/pull/5539)-compliant revocation regsitry on Ethereum.

## Setup

1. Install this plugin
    ```bash
    npm install --save @spherity/tbd @veramo/credential-status
    ```
   
2. Add the plugin to your agent
    ```typescript
   import { CredentialStatusPlugin } from "@veramo/credential-status";
   import { EthrRevocationRegistry } from "@spherity/tbd...";
   ...
    
   export const veramoAgent = createAgent<VeramoAgent>({
      ...,
      plugins: [
        new CredentialStatusPlugin({
          ...new EthrRevocationRegistry(
            "00000000000000",                            // infuraProjectId
            "goerli",                                    // network name
            "0x185D1Cf733e2C85A7Eda4f188036baA5b7a11182" // revocation registry address
          ).asStatusMethod
        }),   
      ],
    });
    ```
## Usage
The revocation check can happen in two ways:
- **Implicitly**: When using Veramo's `agent.verifyCredential({...})` **on LD-credentials**, the verification will automatically do a revocation check in the background. In those cases, you have to wrap this call in a `try-catch` block as a failed verification will results in Veramo throwing an error (`Error: Error verifying LD Verifiable Credential`). **Doing a verification on a credential with a JWT proof won't make this implicit check.**
- **Explicit**: An LD or JWT-credentials revocation status can also be checked explicitly via `veramoAgent.checkCredentialStatus({credential: vc}` where the vc can either be a credential object or a JWT string. This will return a `CredentialStatus` object that has a `revoked` property.

### Example
```typescript
import { CredentialPayload, W3CVerifiableCredential } from '@veramo/core'
import { veramoAgent } from './setup';

async function main() {
  const did = "did:ethr:rinkeby:0x036dffee0bfd09d6a542f57e457cacbb4b0df91fc02bdb478f05d6db085a1da8e8"
  const credential: CredentialPayload = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
      "https://raw.githubusercontent.com/spherity/vc-ethr-revocation-registry/contexts/ethr-revocation-registry.jsonld"
    ],
    "id": "http://example.edu/credentials/58473",
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "issuer": {"id": did},
    "issuanceDate": "2010-01-01T00:00:00Z",
    "credentialSubject": {
      "id": did,
      "degree": {
        "type": "BachelorDegree",
      }
    },
    "credentialStatus": {
      "id": "...",
      "type": "EthrRevocationRegistry",
      "namespace": "0x6B6B873eaB06D331fFA6c431aC874Ff954A2c317",
      "revocationList": "0x3458b9bfc7963978b7d40ef225177c45193c2889902357db3b043a4e319a9628",
      "revocationKey": "0x89343794d2fb7dd5d0fba9593a4bb13beaff93a61577029176d0117b0c53b8e6"
    }
  };

  const verifiableCredential = await veramoAgent.createVerifiableCredential({ credential, proofFormat: "lds", });
   
  // Implicit: Revocation status of LD-credentials are automatically checked during verification
  try {
    await veramoAgent.verifyCredential({credential: verifiableCredential});
    console.log("Valid VC");
  } catch (e) {
    console.log("Invalid VC");
  }
  
  // Explicit: Revocation status of LD-credentials can also be checked explicitly. Mandatory for JWT-credentials.
  const revoked = await veramoAgent.checkCredentialStatus({credential: verifiableCredential})
}

main().catch(console.log)
```