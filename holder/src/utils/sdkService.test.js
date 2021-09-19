import SdkService from './sdkService';
import cloudWalletApi from './apiService';
import { AffinityWallet as Wallet } from '@affinidi/wallet-browser-sdk';
import { __dangerous } from '@affinidi/wallet-core-sdk';
import JwtService from "@affinidi/common/dist/services/JwtService";
import LOCAL_STORAGE_KEY from './consts'

jest.mock('./apiService');
jest.mock('@affinidi/common/dist/services/JwtService');
jest.mock('../config', () => ({
    env: 'someEnv',
    apiKey: 'someApiKey'
}));
jest.mock('@affinidi/wallet-browser-sdk');

const sdkService = new SdkService();
const WalletStorageService = __dangerous.WalletStorageService;
jest.setTimeout(300000);
describe('Test SdkService', () => {
    test('init method', async () => {
        jest.spyOn(Storage.prototype, 'getItem').mockReturnValue('someAccessToken')
        jest.spyOn(Wallet, 'setEnvironmentVarialbles').mockReturnValue({property1: "someProperty"})
        jest.spyOn(WalletStorageService, 'pullEncryptedSeed').mockResolvedValue('someEncryptedSeed');
        jest.spyOn(WalletStorageService, 'pullEncryptionKey').mockResolvedValue('someEncryptedKey');
        await sdkService.init();
        expect(Wallet.setEnvironmentVarialbles).toBeCalled();
        expect(Storage.prototype.getItem).toBeCalledWith(LOCAL_STORAGE_KEY.SDK_ACCESS_TOKEN);
        await expect(WalletStorageService.pullEncryptedSeed).toBeCalled();
        await expect(WalletStorageService.pullEncryptionKey).toBeCalled();
    })

    test('init method no access token', async () => {
        jest.spyOn(Storage.prototype, 'getItem').mockReturnValue(null);
        await expect(sdkService.init).rejects.toBeTruthy();
    })

    test('signOut method', async ()=>{
        jest.spyOn(Storage.prototype, 'removeItem').mockReturnValue();
        await sdkService.signOut();
        await expect(cloudWalletApi.post).toBeCalledWith('/users/logout');
        expect(Storage.prototype.removeItem).toBeCalled();    
    })

    test('signUp method', async ()=>{
        cloudWalletApi.post.mockResolvedValue({
            data: 'someToken'
        })
        await sdkService.signUp('someUsername', 'somePassword', 'someMessageParams');
        await expect(cloudWalletApi.post).toBeCalledWith('/users/signup', {
            username: 'someUsername',
            password: 'somePassword'
        });
    })

    test('confirmSignUp method', async () =>{
        cloudWalletApi.post.mockResolvedValue({data: {accessToken: 'someAccessToken'}});
        jest.spyOn(SdkService, '_saveAccessTokenToLocalStorage');
        await sdkService.confirmSignUp("someAccessToken", "someConfirmationCode");

        await expect(cloudWalletApi.post).toBeCalledWith('/users/signup/confirm', {
            token: 'someAccessToken',
            confirmationCode: 'someConfirmationCode'
        })
        expect(SdkService._saveAccessTokenToLocalStorage).toBeCalledWith('someAccessToken');
    })

    test('getDidAndCredentials method', async () => {
        const testNetworkMember = {
            did: 'someDid',
            getCredentials: jest.fn().mockResolvedValue('someCredentials')
        }
        jest.spyOn(SdkService.prototype, 'init').mockResolvedValue(testNetworkMember);
        jest.spyOn(console, 'log');
        await sdkService.getDidAndCredentials()
        expect(testNetworkMember.getCredentials).toBeCalled();
        expect(console.log).not.toBeCalled();
    })

    test('getDidAndCredentials method will log no credentials if catch an error', async () => {
        const error = new Error('Some error');
        const testNetworkMember = {
            did: 'someDid',
            getCredentials: jest.fn().mockImplementation(() => {
                throw error
            })
        }
        jest.spyOn(SdkService.prototype, 'init').mockResolvedValue(testNetworkMember);
        jest.spyOn(console, 'log').mockImplementation();
        await sdkService.getDidAndCredentials()
        expect(testNetworkMember.getCredentials).toBeCalled();
        expect(console.log).toBeCalledWith('no credentials', error);
    })

    test('fromLoginAndPassword method', async () => {
        cloudWalletApi.post.mockResolvedValue({data: {accessToken: 'someAccessToken'}});
        jest.spyOn(SdkService, '_saveAccessTokenToLocalStorage');
        await sdkService.fromLoginAndPassword('someUsername', 'somePassword');
        expect(cloudWalletApi.post).toBeCalledWith('/users/login', {
            username: 'someUsername',
            password: 'somePassword'
        });
        expect(SdkService._saveAccessTokenToLocalStorage).toBeCalledWith('someAccessToken');
    })

    test('getCredentials method', async () => {
        const testNetworkMember = {
            did: 'someDid',
            getCredentials: jest.fn()
        }
        jest.spyOn(SdkService.prototype, 'init').mockResolvedValue(testNetworkMember);

        await sdkService.getCredentials('someCredentialShareRequestToken', 'someFetchBackupCredentials');
        await expect(sdkService.init).toBeCalled();
        await expect(testNetworkMember.getCredentials).toBeCalledWith('someCredentialShareRequestToken', 'someFetchBackupCredentials');
    })

    test('saveCredentials method', async () => {
        const testNetworkMember = {
            did: 'someDid',
            saveCredentials: jest.fn()
        }
        jest.spyOn(SdkService.prototype, 'init').mockResolvedValue(testNetworkMember);

        await sdkService.saveCredentials('someCredentials');
        await expect(sdkService.init).toBeCalled();
        await expect(testNetworkMember.saveCredentials).toBeCalledWith('someCredentials');
    })

    test('createCredentialShareResponseToken method', async () => {
        const testNetworkMember = {
            did: 'someDid',
            createCredentialShareResponseToken: jest.fn()
        }
        jest.spyOn(SdkService.prototype, 'init').mockResolvedValue(testNetworkMember);

        await sdkService.createCredentialShareResponseToken('someCredentials', 'someSuppliedCredentials');
        await expect(sdkService.init).toBeCalled();
        await expect(testNetworkMember.createCredentialShareResponseToken).toBeCalledWith('someCredentials', 'someSuppliedCredentials');
    })

    test('parseToken method', () => {
        sdkService.parseToken('someAccessToken');
        expect(JwtService.fromJWT).toBeCalledWith('someAccessToken');
    })

    test('_saveAccessTokenToLocalStorage method', ()=>{
        jest.spyOn(console, 'error').mockImplementation();
        jest.spyOn(global.localStorage.__proto__, 'setItem').mockImplementation(() => {
          throw new Error('No reason')
        })
    
        SdkService._saveAccessTokenToLocalStorage('someAccessToken');
        
        expect(global.localStorage.__proto__.setItem).toBeCalled()
        expect(console.error).toHaveBeenCalled()
    })

    afterEach(()=>{
        jest.restoreAllMocks()
    });
})