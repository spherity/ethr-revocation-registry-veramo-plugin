import { EthrRevocationRegistry } from '../ethr-revocation-registry'
import { DIDDocument } from '@veramo/core';

jest.mock('@spherity/ethr-revocation-registry-controller', () => ({
  EthereumRevocationRegistryController: jest.fn().mockImplementation(() => ({
    isRevoked: jest.fn().mockResolvedValue(false)
  }))
}));

describe ('EthrRevocationRegistryPlugin', () => {
  let pluginInstance: EthrRevocationRegistry;
  const didDoc = {} as DIDDocument;

  beforeEach(() => {
    pluginInstance = new EthrRevocationRegistry("", "", "");
  })

  it('should return a status method when supplied a credential object', async () => {
    const credential = {
      credentialStatus: {
        id: "0",
        type: "EthrRevocationRegistry",
        revocationKey: "0x89343794d2fb7dd5d0fba9593a4bb13beaff93a61577029176d0117b0c53b8e6",
        revocationList: "0x3458b9bfc7963978b7d40ef225177c45193c2889902357db3b043a4e319a9627",
        namespace: "0x6B6B873eaB06D331fFA6c431aC874Ff954A2c317"
      }
    }
    const result = await pluginInstance.checkStatus(credential, didDoc)
    expect(result).toEqual({ revoked: false })

  })

  it('should return a status method when supplied a jwt string vc', async () => {
    const credential = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIiwiaHR0cHM6Ly9zcGhlcml0eS5naXRodWIuaW8vdmMtZXRoci1zdGF0dXMtcmVnaXN0cnkvZXRoci1yZXZvY2F0aW9uLXJlZ2lzdHJ5Lmpzb25sZCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImRlZ3JlZSI6eyJ0eXBlIjoiQmFjaGVsb3JEZWdyZWUifX0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL2V4YW1wbGUuZWR1L3N0YXR1cy8yNCIsInR5cGUiOiJFdGhyUmV2b2NhdGlvblJlZ2lzdHJ5IiwibmFtZXNwYWNlIjoiMHg2QjZCODczZWFCMDZEMzMxZkZBNmM0MzFhQzg3NEZmOTU0QTJjMzE3IiwicmV2b2NhdGlvbkxpc3QiOiIweDM0NThiOWJmYzc5NjM5NzhiN2Q0MGVmMjI1MTc3YzQ1MTkzYzI4ODk5MDIzNTdkYjNiMDQzYTRlMzE5YTk2MjciLCJyZXZvY2F0aW9uS2V5IjoiMHg4OTM0Mzc5NGQyZmI3ZGQ1ZDBmYmE5NTkzYTRiYjEzYmVhZmY5M2E2MTU3NzAyOTE3NmQwMTE3YjBjNTNiOGU2In19LCJzdWIiOiJkaWQ6ZXRocjpyaW5rZWJ5OjB4MDM2ZGZmZWUwYmZkMDlkNmE1NDJmNTdlNDU3Y2FjYmI0YjBkZjkxZmMwMmJkYjQ3OGYwNWQ2ZGIwODVhMWRhOGU4IiwianRpIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzU4NDczIiwibmJmIjoxMjYyMzA0MDAwLCJpc3MiOiJkaWQ6ZXRocjpyaW5rZWJ5OjB4MDM2ZGZmZWUwYmZkMDlkNmE1NDJmNTdlNDU3Y2FjYmI0YjBkZjkxZmMwMmJkYjQ3OGYwNWQ2ZGIwODVhMWRhOGU4In0.VDkbwLBeoaaKej59O_xCjYmVroYiGDI7wjp9NpHBn4Re4FORbNmOVU6FbL7ybVJxwkIuiyO_GsTho2PNU-0hbQ"
    const result = await pluginInstance.checkStatus(credential, didDoc)
    expect(result).toEqual({ revoked: false })
  })

  it('should handle credential provided as string', async () => {
    const extractedNamespace = "0x6B6B873eaB06D331fFA6c431aC874Ff954A2c317";
    const extractedRevocationList = "0x3458b9bfc7963978b7d40ef225177c45193c2889902357db3b043a4e319a9627";
    const extractedRevocationKey = "0x89343794d2fb7dd5d0fba9593a4bb13beaff93a61577029176d0117b0c53b8e6";
    const credential = `{ "credentialStatus": { "id": "", "type": "EthrRevocationRegistry", "namespace": "${extractedNamespace}", "revocationList": "${extractedRevocationList}", "revocationList": "${extractedRevocationList}", "revocationKey": "${extractedRevocationKey}"}}`;
    const result = await pluginInstance.checkStatus(credential, didDoc)
    expect(result).toEqual({ revoked: false })
  })

  it('should return false with message for jwt without credentialStatus object', async () => {
    const credential = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    const result = await pluginInstance.checkStatus(credential, didDoc)
    expect(result).toEqual({ message: "credentialStatus property was not set on the original credential", revoked: false })
  })

  it('should handle string credential without credentialStatus object', async () => {
    const credential = "{}"
    const result = await pluginInstance.checkStatus(credential, didDoc)
    expect(result).toEqual({ message: "credentialStatus property was not set on the original credential", revoked: false })
  })

  it('should handle string credential without type in credentialStatus object', async () => {
    const extractedNamespace = "0x6B6B873eaB06D331fFA6c431aC874Ff954A2c317";
    const extractedRevocationList = "0x3458b9bfc7963978b7d40ef225177c45193c2889902357db3b043a4e319a9627";
    const extractedRevocationKey = "0x89343794d2fb7dd5d0fba9593a4bb13beaff93a61577029176d0117b0c53b8e6";
    const credential = `{ "credentialStatus": { "id": "", "namespace": "${extractedNamespace}", "revocationList": "${extractedRevocationList}", "revocationList": "${extractedRevocationList}", "revocationKey": "${extractedRevocationKey}"}}`;
    await expect(pluginInstance.checkStatus(credential, didDoc)).rejects.toEqual(new Error("bad_request: credentialStatus entry is not formatted correctly. Validity can not be determined."))
  })
})


