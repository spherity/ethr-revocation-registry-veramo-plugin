import { CredentialJwtOrJSON, StatusMethod, StatusResolver } from 'credential-status';
import {
  EthereumRevocationRegistryController,
} from '@spherity/ethr-revocation-registry-controller';
import {ethers, JsonRpcProvider, Provider} from 'ethers';
import { decodeJWT } from 'did-jwt';
import { StatusEntry } from 'credential-status/src';
import {getRevocationRegistryDeploymentAddress} from "@spherity/ethr-revocation-registry";

export interface EthrRevocationRegistryConfig {
  infuraProjectId?: string;
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
  address: string;
  provider: Provider;
}

type ChainIdInfuraSubdomainPair = {
  chainId: number;
  subdomain: string;
}

const chainIdInfuraSubdomains: ChainIdInfuraSubdomainPair[] = [
  {
    chainId: 1,
    subdomain: "mainnet"
  },
  {
    chainId: 5,
    subdomain: "goerli"
  },
  {
    chainId: 11155111,
    subdomain: "sepolia"
  }
]

const defaultMainnetAddress = getRevocationRegistryDeploymentAddress(5)

export class EthrRevocationRegistry implements StatusResolver {
  infuraProjectId?: string;
  controllers: RegistryControllers = {};

  constructor(config: EthrRevocationRegistryConfig) {
    if (config.infuraProjectId) {
      this.infuraProjectId = config.infuraProjectId;

      chainIdInfuraSubdomains.forEach((pair) => {
        try {
          const address = getRevocationRegistryDeploymentAddress(pair.chainId)
          if(!this.controllers[address]) this.controllers[address] = {};
          this.controllers[address][pair.chainId] = new EthereumRevocationRegistryController({
            address,
            provider: new JsonRpcProvider(`https://${pair.subdomain}.infura.io/v3/${this.infuraProjectId}`),
          })
        } catch (error) {
          // tslint:disable-next-line:no-console
          console.log(`Error creating the EthereumRevocationRegistryController for chainId '${pair.chainId}'!`)
        }
      });
    } else if (config.chainConnectionInstructions) {
      config.chainConnectionInstructions.forEach(instruction => {
        this.controllers[instruction.address] = {
          [instruction.chainId]: new EthereumRevocationRegistryController({
            address: instruction.address,
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
      // Respect the VC's chainId and if available the registry address.
      let registry;
      if(!statusEntry.registry) {
        try {
          registry = getRevocationRegistryDeploymentAddress(statusEntry.chainId);
        } catch(error) {
          throw new Error(`ChainId found but address is missing in credential status. Error: ${error}`)
        }
      } else {
        registry = statusEntry.registry;
      }

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
      const controller = this.controllers[defaultMainnetAddress][5];
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
  asStatusMethod = { EthrRevocationRegistry2022: this.checkStatus };
}
