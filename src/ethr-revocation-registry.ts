import { CredentialJwtOrJSON, StatusMethod, StatusResolver } from 'credential-status';
import {
  EthereumRevocationRegistryController,
  EthereumRevocationRegistryControllerConfig,
} from '@spherity/ethr-revocation-registry-controller';
import { ethers } from 'ethers';
import { JsonRpcProvider } from '@ethersproject/providers';
import { decodeJWT } from 'did-jwt';
import { StatusEntry } from 'credential-status/src';

export class EthrRevocationRegistry implements StatusResolver {
  provider: JsonRpcProvider;
  controller: EthereumRevocationRegistryController;

  constructor(infuraProjectId?: string, networkName?: string, registryAddress?: string) {
    this.provider = new ethers.providers.JsonRpcProvider(`https://${networkName}.infura.io/v3/${infuraProjectId}`);
    const config: EthereumRevocationRegistryControllerConfig = {
      provider: this.provider,
      address: registryAddress,
    };
    this.controller = new EthereumRevocationRegistryController(config);
  }
  checkStatus: StatusMethod = async (credential: CredentialJwtOrJSON) => {
    let statusEntry: StatusEntry | undefined;
    if (typeof credential === 'string') {
      try {
        const decoded = decodeJWT(credential);
        statusEntry =
          decoded?.payload?.vc?.credentialStatus || // JWT Verifiable Credential payload
          decoded?.payload?.vp?.credentialStatus || // JWT Verifiable Presentation payload
          decoded?.payload?.credentialStatus; // legacy JWT payload
      } catch (e1: unknown) {
        // not a JWT credential or presentation
        try {
          const decoded = JSON.parse(credential);
          statusEntry = decoded?.credentialStatus;
        } catch (e2: unknown) {
          // not a JSON either.
        }
      }
    } else {
      statusEntry = credential.credentialStatus;
    }
    if (!statusEntry) {
      return {
        revoked: false,
        message: 'credentialStatus property was not set on the original credential',
      };
    } else if (typeof statusEntry !== 'object' || !statusEntry?.type) {
      throw new Error(
        'bad_request: credentialStatus entry is not formatted correctly. Validity can not be determined.',
      );
    }
    const revoked = await this.controller.isRevoked({
      namespace: statusEntry.namespace,
      list: statusEntry.revocationList,
      revocationKey: statusEntry.revocationKey,
    });
    return { revoked };
  };
  asStatusMethod = { EthrRevocationRegistry: this.checkStatus };
}
