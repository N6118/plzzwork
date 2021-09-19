import AffinidiDidAuthService from "@affinidi/affinidi-did-auth-lib/dist/DidAuthService/DidAuthService";
import SdkService from "./SdkService";
import config from "../config";

export class MessageService {
  private static readonly MESSAGE_SERVICE_BASE_URL =
    config.messagesBaseUrl + "/api/v1";
  private static readonly DEFAULT_HEADERS = {
    "Content-Type": "application/json",
  };

  private readonly _affinidiDidAuthService: AffinidiDidAuthService;
  private _token: string | null = null;

  constructor(private readonly _sdkService: SdkService) {
    this._affinidiDidAuthService = new AffinidiDidAuthService({
      encryptedSeed: this._sdkService.encryptedSeed,
      encryptionKey: this._sdkService.encryptionKey,
    });
  }

  async send(did: any, message: any): Promise<void> {
    const encryptedMessage = await this._sdkService.createEncryptedMessage(
      did,
      message
    );

    const token = await this.getToken();
    return this.execute("/messages", "POST", token, {
      toDid: did,
      message: encryptedMessage,
    });
  }

  async getAll(): Promise<any[]> {
    const token = await this.getToken();
    const { messages } = await this.execute("/messages", "GET", token);

    return Promise.all(
      messages.map(async ({ id, fromDid, createdAt, message }: any) => {
        const decrypted = await this._sdkService.readEncryptedMessage(message);

        return { id, fromDid, createdAt, message: decrypted };
      })
    );
  }

  async delete(id: string): Promise<void> {
    const token = await this.getToken();
    return this.execute("/message/" + id, "DELETE", token);
  }

  private async getToken(): Promise<string> {
    if (
      this._token &&
      !this._affinidiDidAuthService.isTokenExpired(this._token)
    ) {
      return this._token;
    }

    const audienceDid = this._sdkService.did;

    const requestToken = await this.execute(
      "/did-auth/create-did-auth-request",
      "POST",
      undefined,
      { audienceDid }
    );

    const token = await this._affinidiDidAuthService.createDidAuthResponseToken(
      requestToken
    );

    return (this._token = token);
  }

  private async execute(
    path: string,
    method: string,
    token?: string,
    data?: any
  ): Promise<any> {
    const url = MessageService.buildUrl(path);
    const response = await fetch(url, {
      method: method,
      mode: "cors",
      cache: "no-cache",
      credentials: "omit",
      headers: {
        ...MessageService.DEFAULT_HEADERS,
        "Api-Key": this._sdkService.accessApiKey,
        ...(token ? { Authorization: "Bearer " + token } : {}),
      },
      body: JSON.stringify(data),
    });

    if (response.status < 200 || response.status > 299) {
      throw new Error(`${url} responded with ${response.statusText}`);
    }

    if (response.status === 204) {
      return undefined;
    }

    return response.json();
  }

  private static buildUrl(path: string) {
    return this.MESSAGE_SERVICE_BASE_URL + path;
  }
}
