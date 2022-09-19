import { CredentialJwtOrJSON, StatusMethod, StatusResolver } from 'credential-status';
import {
  EthereumRevocationRegistryController,
} from '@spherity/ethr-revocation-registry-controller';
import { ethers } from 'ethers';
import { decodeJWT } from 'did-jwt';
import { StatusEntry } from 'credential-status/src';

type ChainControllers = {
  [chainId: number]: EthereumRevocationRegistryController;
};

export class EthrRevocationRegistry implements StatusResolver {
  controllers: ChainControllers;

  constructor(infuraProjectId?: string, registryAddress?: string) {
    this.controllers = {
      1: new EthereumRevocationRegistryController({
        address: registryAddress,
        provider: new ethers.providers.JsonRpcProvider(`https://mainnet.infura.io/v3/${infuraProjectId}`),
      }),
      3: new EthereumRevocationRegistryController({
        address: registryAddress,
        provider: new ethers.providers.JsonRpcProvider(`https://ropsten.infura.io/v3/${infuraProjectId}`),
      }),
      42: new EthereumRevocationRegistryController({
        address: registryAddress,
        provider: new ethers.providers.JsonRpcProvider(`https://kovan.infura.io/v3/${infuraProjectId}`),
      }),
      4: new EthereumRevocationRegistryController({
        address: registryAddress,
        provider: new ethers.providers.JsonRpcProvider(`https://rinkeby.infura.io/v3/${infuraProjectId}`),
      }),
      5: new EthereumRevocationRegistryController({
        address: registryAddress,
        provider: new ethers.providers.JsonRpcProvider(`https://goerli.infura.io/v3/${infuraProjectId}`),
      }),
      11155111: new EthereumRevocationRegistryController({
        address: registryAddress,
        provider: new ethers.providers.JsonRpcProvider(`https://sepolia.infura.io/v3/${infuraProjectId}`),
      }),
    };
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
    let revoked: boolean;
    if (statusEntry.chainId && !this.controllers[statusEntry.chainId]) {
      throw new Error('bad_request: chainId is not supported');
    } else if (!statusEntry.chainId) {
      revoked = await this.controllers[1].isRevoked({
        namespace: statusEntry.namespace,
        list: statusEntry.revocationList,
        revocationKey: statusEntry.revocationKey,
      });
    } else {
      revoked = await this.controllers[statusEntry.chainId].isRevoked({
        namespace: statusEntry.namespace,
        list: statusEntry.revocationList,
        revocationKey: statusEntry.revocationKey,
      });
    }
    return { revoked };
  };
  asStatusMethod = { EthrRevocationRegistry: this.checkStatus };
}
