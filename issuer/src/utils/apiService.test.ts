import {cloudWalletApi, issuerApi} from 'utils/api';
import {endpoints} from 'constants/endpoints';
import ApiService from 'utils/apiService';
import {drivingLicenseVCData, signedDrivingLicenseVC, unsignedDrivingLicenseVC} from 'utils/vc-data-examples/drivinglicense';

let mockCloudWalletApiPost: jest.SpyInstance
let mockCloudWalletApiGet: jest.SpyInstance
let mockCloudWalletApiDelete: jest.SpyInstance
let mockIssuerApiPost: jest.SpyInstance
let mockStoreAccessAndDidToken: jest.SpyInstance
let mockSetAuthorizationBearer: jest.SpyInstance
let mockSaveAccessTokenToLocalStorage: jest.SpyInstance
let mockSaveDidTokenToLocalStorage: jest.SpyInstance
let mockRemoveAccessTokenFromLocalStorage: jest.SpyInstance
let mockRemoveDidTokenFromLocalStorage: jest.SpyInstance

beforeEach(() => {
  mockCloudWalletApiPost = jest.spyOn(cloudWalletApi, 'post');
  mockCloudWalletApiGet = jest.spyOn(cloudWalletApi, 'get');
  mockCloudWalletApiDelete = jest.spyOn(cloudWalletApi, 'delete');
  mockIssuerApiPost = jest.spyOn(issuerApi, 'post');
  mockStoreAccessAndDidToken = jest.spyOn(ApiService, 'storeAccessAndDidTokens');
  mockSetAuthorizationBearer = jest.spyOn(ApiService, 'setAuthorizationBearer');
  mockSaveAccessTokenToLocalStorage = jest.spyOn(ApiService, 'saveAccessTokenToLocalStorage');
  mockSaveDidTokenToLocalStorage = jest.spyOn(ApiService, 'saveDidTokenToLocalStorage');
  mockRemoveAccessTokenFromLocalStorage = jest.spyOn(ApiService, 'removeAccessTokenFromLocalStorage');
  mockRemoveDidTokenFromLocalStorage = jest.spyOn(ApiService, 'removeDidTokenFromLocalStorage');
});

describe('ApiService methods', () => {
  const username = 'test';
  const password = 'test';
  const accessToken = 'accessToken';
  const did = 'did';

  test('signUp method', async () => {
    mockCloudWalletApiPost.mockImplementation(() => Promise.resolve({
      accessToken,
      did
    }));

    await ApiService.signUp(username,password)

    expect(mockCloudWalletApiPost).toHaveBeenCalledWith(endpoints.SIGNUP, {username, password})
  })

  test('logIn method', async () => {
    mockCloudWalletApiPost.mockImplementation(() => Promise.resolve({
      accessToken,
      did
    }));

    await ApiService.logIn(username,password)

    expect(mockCloudWalletApiPost).toHaveBeenCalledWith(endpoints.LOGIN, {username, password})
  })

  test('clientSideLogin method', async () => {
    ApiService.clientSideLogIn(accessToken, did);

    expect(mockStoreAccessAndDidToken).toBeCalledWith(accessToken, did);
    expect(mockSetAuthorizationBearer).toBeCalledWith(accessToken);

    expect(mockStoreAccessAndDidToken).toBeCalledTimes(1);
    expect(mockSetAuthorizationBearer).toBeCalledTimes(1);

  })

  test('logout method', async () => {
    mockCloudWalletApiPost.mockImplementation(() => Promise.resolve());

    await ApiService.logout()

    expect(mockCloudWalletApiPost).toHaveBeenCalledWith(endpoints.LOGOUT)
  })

  test('issueUnsignedVC method', async () => {
    const example = {...drivingLicenseVCData}
    example.holderDid = '';

    mockIssuerApiPost.mockImplementation(() => Promise.resolve({
      unsignedVC: unsignedDrivingLicenseVC
    }));

    await ApiService.issueUnsignedVC(drivingLicenseVCData)

    expect(mockIssuerApiPost).toHaveBeenCalledWith(endpoints.VC_BUILD_UNSIGNED, example)
  })

  test('signVC method', async () => {
    mockCloudWalletApiPost.mockImplementation(() => Promise.resolve({
      unsignedVC: unsignedDrivingLicenseVC
    }));

    const input = {
      unsignedCredential: unsignedDrivingLicenseVC
    }

    await ApiService.signVC(input)

    expect(mockCloudWalletApiPost).toHaveBeenCalledWith(endpoints.WALLET_SIGN_CREDENTIALS, input)
  })

  test('storeSignedVCs method', async () => {
    mockCloudWalletApiPost.mockImplementation(() => Promise.resolve({
      errors: [],
      isValid: true
    }));

    const input = {
      data: [signedDrivingLicenseVC]
    }

    await ApiService.storeSignedVCs(input)

    expect(mockCloudWalletApiPost).toHaveBeenCalledWith(endpoints.WALLET_CREDENTIALS, input)
  })

  test('getSavedVCs method', async () => {
    mockCloudWalletApiGet.mockImplementation(() => [signedDrivingLicenseVC]);

    await ApiService.getSavedVCs();

    expect(mockCloudWalletApiGet).toHaveBeenCalledWith(endpoints.WALLET_CREDENTIALS)
    expect(mockCloudWalletApiGet.mock.results[0].value).toStrictEqual([signedDrivingLicenseVC])
  })

  test('deleteStoredVC method', async () => {
    mockCloudWalletApiDelete.mockImplementation(() => Promise.resolve());
    const vcId = '1';

    await ApiService.deleteStoredVC(vcId);

    expect(mockCloudWalletApiDelete).toHaveBeenCalledWith(`${endpoints.WALLET_CREDENTIALS}/${vcId}`)
  })

  test('storeAccessAndDidTokens method', async () => {
    ApiService.storeAccessAndDidTokens(accessToken, did);
    expect(mockSaveAccessTokenToLocalStorage).toBeCalledWith(accessToken);
    expect(mockSaveDidTokenToLocalStorage).toBeCalledWith(did);

    expect(mockSaveAccessTokenToLocalStorage).toBeCalledTimes(1);
    expect(mockSaveDidTokenToLocalStorage).toBeCalledTimes(1);
  })

  test('removeAccessAndDidTokens method', async ()=>{
    ApiService.removeAccessAndDidTokens()
    expect(mockRemoveAccessTokenFromLocalStorage).toBeCalledTimes(1);
    expect(mockRemoveDidTokenFromLocalStorage).toBeCalledTimes(1);
  })

  test('setAuthorizationBearer method', async () => {
    ApiService.setAuthorizationBearer(accessToken);
    expect(cloudWalletApi.defaults.headers.common['Authorization']).toMatch(`Bearer ${accessToken}`);
  })

  test('saveAccessTokenToLocalStorage method', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(global.localStorage.__proto__, 'setItem').mockImplementation(() => {
      throw new Error('No reason')
    })

    ApiService.saveAccessTokenToLocalStorage(accessToken)

    expect(console.error).toHaveBeenCalled()
  })

  test('getAccessTokenFromLocalStorage method', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(global.localStorage.__proto__, 'getItem').mockImplementation(() => {
      throw new Error('No reason')
    })

    ApiService.getAccessTokenFromLocalStorage()

    expect(console.error).toHaveBeenCalled()
  })

  test('removeAccessTokenFromLocalStorage method', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(global.localStorage.__proto__, 'removeItem').mockImplementation(() => {
      throw new Error('No reason')
    })

    ApiService.removeAccessTokenFromLocalStorage()

    expect(console.error).toHaveBeenCalled()
  })

  test('saveDidTokenToLocalStorage method', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(global.localStorage.__proto__, 'setItem').mockImplementation(() => {
      throw new Error('No reason')
    })

    ApiService.saveDidTokenToLocalStorage('test')

    expect(console.error).toHaveBeenCalled()
  })

  test('getDidTokenToLocalStorage method', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(global.localStorage.__proto__, 'getItem').mockImplementation(() => {
      throw new Error('No reason')
    })

    ApiService.getDidTokenToLocalStorage()

    expect(console.error).toHaveBeenCalled()
  })

  test('removeDidTokenFromLocalStorage method', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {})
    jest.spyOn(global.localStorage.__proto__, 'removeItem').mockImplementation(() => {
      throw new Error('No reason')
    })

    ApiService.removeDidTokenFromLocalStorage()

    expect(console.error).toHaveBeenCalled()
  })

  test('alertWithBrowserConsole method', () => {
    jest.spyOn(console, 'log').mockImplementation();
    jest.spyOn(window, 'alert').mockImplementation();
    const consoleMessage = 'Test console error message';
    const alertMessage = 'Test alert error message';
    ApiService.alertWithBrowserConsole(consoleMessage, alertMessage);

    expect(console.log).toHaveBeenCalled()
    expect(console.log).toHaveBeenCalledWith(consoleMessage)
    expect(alert).toHaveBeenCalled()
    expect(alert).toHaveBeenCalledWith(alertMessage)
  })

  test("shareCredentials method", async () => {
    const testClaimID = 'testClaimID';
    const returnData = {
      qrCode: "testQRCode",
      sharingUrl: "testSharingURL"
    }
    mockCloudWalletApiPost.mockImplementation(()=>{
      const a = {
        data: returnData
      }
      return a;
    })
    ApiService.shareCredentials(testClaimID);
    expect(mockCloudWalletApiPost).toBeCalledWith(`${endpoints.WALLET_CREDENTIALS}/${testClaimID}/share`)
  })

  afterEach(()=>{
    mockStoreAccessAndDidToken.mockRestore()
    mockSetAuthorizationBearer.mockRestore()
    mockSaveAccessTokenToLocalStorage.mockRestore()
    mockSaveDidTokenToLocalStorage.mockRestore()
    mockRemoveAccessTokenFromLocalStorage.mockRestore()
    mockRemoveDidTokenFromLocalStorage.mockRestore()
  })
})

export {}