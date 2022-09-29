import { CredentialJwtOrJSON, StatusMethod, StatusResolver } from 'credential-status';
import {
  EthereumRevocationRegistryController,
} from '@spherity/ethr-revocation-registry-controller';
import { ethers } from 'ethers';
import { Provider } from '@ethersproject/providers';
import { decodeJWT } from 'did-jwt';
import { StatusEntry } from 'credential-status/src';

export interface EthrRevocationRegistryConfig {
  infuraProjectId?: string;
  defaultRegistryAddress?: string;
  chainConnectionInstructions?: ChainConnectionInstruction[];
}

type ChainConnection = {
  [chainId: number]: EthereumRevocationRegistryController;
}

type RegistryControllers = {
  [registryAddress: string]: ChainConnection;
}

type ChainConnectionInstruction = {
  chainId: number;
  provider: Provider;
}

export class EthrRevocationRegistry implements StatusResolver {
  infuraProjectId?: string;
  defaultRegistryAddress?: string;
  controllers?: RegistryControllers;

  constructor(config: EthrRevocationRegistryConfig) {
    if (config.infuraProjectId && config.defaultRegistryAddress) {
      this.infuraProjectId = config.infuraProjectId;
      this.defaultRegistryAddress = config.defaultRegistryAddress;
      this.controllers = {
        [this.defaultRegistryAddress]: {
          1: new EthereumRevocationRegistryController({
            address: this.defaultRegistryAddress,
            provider: new ethers.providers.JsonRpcProvider(`https://mainnet.infura.io/v3/${this.infuraProjectId}`),
          }),
          3: new EthereumRevocationRegistryController({
            address: this.defaultRegistryAddress,
            provider: new ethers.providers.JsonRpcProvider(`https://ropsten.infura.io/v3/${this.infuraProjectId}`),
          }),
          42: new EthereumRevocationRegistryController({
            address: this.defaultRegistryAddress,
            provider: new ethers.providers.JsonRpcProvider(`https://kovan.infura.io/v3/${this.infuraProjectId}`),
          }),
          4: new EthereumRevocationRegistryController({
            address: this.defaultRegistryAddress,
            provider: new ethers.providers.JsonRpcProvider(`https://rinkeby.infura.io/v3/${this.infuraProjectId}`),
          }),
          5: new EthereumRevocationRegistryController({
            address: this.defaultRegistryAddress,
            provider: new ethers.providers.JsonRpcProvider(`https://goerli.infura.io/v3/${this.infuraProjectId}`),
          }),
          11155111: new EthereumRevocationRegistryController({
            address: this.defaultRegistryAddress,
            provider: new ethers.providers.JsonRpcProvider(`https://sepolia.infura.io/v3/${this.infuraProjectId}`),
          }),
        },
      };
    } else if (config.chainConnectionInstructions && config.defaultRegistryAddress) {
      this.defaultRegistryAddress = config.defaultRegistryAddress;
      if (!this.controllers) {
        this.controllers = { [this.defaultRegistryAddress]: {} };
      }
      config.chainConnectionInstructions.forEach(instruction => {
        this.controllers![this.defaultRegistryAddress!] = {
          [instruction.chainId]: new EthereumRevocationRegistryController({
            address: this.defaultRegistryAddress,
            provider: instruction.provider,
          }),
        };
      });
    } else {
      throw new Error('EthrRevocationRegistry requires either an infuraProjectId and defaultRegistryAddress, or a ChainConnectionInstruction array');
    }
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
        'credentialStatus entry is not formatted correctly. Validity can not be determined.',
      );
    }

    let revoked: boolean;

    if (statusEntry.chainId) {
      // Respect VC's the chainId and if available the registry address.
      const registry = statusEntry.registry ?? this.defaultRegistryAddress;
      const controller = this.controllers![registry][statusEntry.chainId];
      if (!controller) {
        throw new Error(`No revocation controller found for specified chainId/ revocation registry address. Recheck plugins configuration.`);
      }
      revoked = await controller.isRevoked({
        namespace: statusEntry.namespace,
        list: statusEntry.revocationList,
        revocationKey: statusEntry.revocationKey,
      });
    } else {
      // If VC doesn't specify registry address & chainId, use provided default registry address and lookup on mainnet
      const controller = this.controllers![this.defaultRegistryAddress!][1];
      if (!controller) {
        throw new Error(`No revocation controller found for default mainnet. Recheck plugins configuration.`);
      }
      revoked = await controller.isRevoked({
        namespace: statusEntry.namespace,
        list: statusEntry.revocationList,
        revocationKey: statusEntry.revocationKey,
      });
    }
    return { revoked };
  };
  asStatusMethod = { EthrRevocationRegistry: this.checkStatus };
}
