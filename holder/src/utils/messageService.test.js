import AffinidiDidAuthService from "@affinidi/affinidi-did-auth-lib/dist/DidAuthService/DidAuthService";
import {MessageService} from './messageService'


jest.mock('@affinidi/affinidi-did-auth-lib/dist/DidAuthService/DidAuthService');

let testNetworkMember;
let messageService;

beforeEach(()=>{
    testNetworkMember = {
        encryptedSeed: 'someEncryptedSeed',
        password: 'somePassword',
        createEncryptedMessage: jest.fn().mockResolvedValue('someEncryptedMessage'),
        readEncryptedMessage: jest.fn().mockResolvedValue('someDecryptedMessage'),
        did: 'someDid',
    }
    messageService = new MessageService(testNetworkMember)
})


describe('Test MessageService', () => {

    test('send method', async () => {
        jest.spyOn(MessageService.prototype, 'getToken').mockResolvedValue('someToken');
        jest.spyOn(MessageService.prototype, 'execute').mockReturnValue({
            messages: [
                {
                    id: 'someId',
                    fromDid: 'someDid',
                    createdAt: 'someDateTime',
                    message: 'someMessage'
                }
            ]
        });
        await messageService.send('someDid', 'someMessage');
        await expect(testNetworkMember.createEncryptedMessage).toBeCalledWith('someDid', 'someMessage');
        await expect(MessageService.prototype.getToken).toBeCalled();
        await expect(MessageService.prototype.execute).toBeCalledWith(
            '/messages',
            'POST',
            'someToken',
            {
                toDid: 'someDid',
                message: 'someEncryptedMessage'
            }
        )
    })

    test('getAll method', async () => {
        jest.spyOn(MessageService.prototype, 'getToken').mockResolvedValue('someToken');
        jest.spyOn(MessageService.prototype, 'execute').mockReturnValue({
            messages: [
                {
                    id: 'someId',
                    fromDid: 'someDid',
                    createdAt: 'someDateTime',
                    message: 'someMessage'
                }
            ]
        });
        await messageService.getAll();
        await expect(MessageService.prototype.getToken).toBeCalled()
        await expect(MessageService.prototype.execute).toBeCalledWith(
            '/messages',
            'GET',
            'someToken'
        );
        await expect(testNetworkMember.readEncryptedMessage).toBeCalledWith('someMessage');
    })

    test('delete method', async ()=>{
        jest.spyOn(MessageService.prototype, 'getToken').mockResolvedValue('someToken');
        jest.spyOn(MessageService.prototype, 'execute').mockReturnValue({
            messages: [
                {
                    id: 'someId',
                    fromDid: 'someDid',
                    createdAt: 'someDateTime',
                    message: 'someMessage'
                }
            ]
        });
        await messageService.delete('someId');
        await expect(MessageService.prototype.getToken).toBeCalled()
        await expect(MessageService.prototype.execute).toBeCalledWith(
            '/message/someId',
            'DELETE',
            'someToken'
        );
    })

    test('getToken method, token is expired and token is null', async ()=>{
        jest.spyOn(MessageService.prototype, 'execute').mockReturnValue('someRequestToken');
        AffinidiDidAuthService.prototype.isTokenExpired.mockReturnValue(true);
        AffinidiDidAuthService.prototype.createDidAuthResponseToken.mockResolvedValue('someToken');
        const token = await messageService.getToken()
        await expect(MessageService.prototype.execute).toBeCalledWith(
            "/did-auth/create-did-auth-request",
            "POST",
            undefined,
            { 
                audienceDid: 'someDid'
            }
        );
        await expect(AffinidiDidAuthService.prototype.createDidAuthResponseToken).toBeCalledWith('someRequestToken');
        expect(token).toEqual('someToken');
    })

    test('getToken method, token is not expired and there is a token', async ()=>{
        AffinidiDidAuthService.prototype.isTokenExpired.mockReturnValue(false);
        messageService._token = 'someToken'
        const token = await messageService.getToken();
        expect(token).toEqual('someToken');
    })

    test('execute method, status code 200', async ()=>{
        jest.spyOn(MessageService, 'buildUrl').mockReturnValue('someUrl');
        jest.spyOn(global, 'fetch').mockResolvedValue({
            status: 200,
            json: jest.fn().mockReturnValue('someObj')
        })

        const jsonValue = await  messageService.execute('somePath', 'GET', 'someToken', 'someData');

        await expect(global.fetch).toBeCalled()
        expect(jsonValue).toEqual('someObj');
    })

    test('execute method, status code 204', async ()=>{
        jest.spyOn(MessageService, 'buildUrl').mockReturnValue('someUrl');
        jest.spyOn(global, 'fetch').mockResolvedValue({
            status: 204,
            json: jest.fn().mockReturnValue('someObj')
        })

        const jsonValue = await  messageService.execute('somePath', 'GET', 'someToken', 'someData');

        await expect(global.fetch).toBeCalled();
        expect(jsonValue).toEqual(undefined);
    })

    test('execute method, status code < 200 || > 299', async ()=>{
        jest.spyOn(MessageService, 'buildUrl').mockReturnValue('someUrl');
        jest.spyOn(global, 'fetch').mockResolvedValue({
            status: 500,
            json: jest.fn().mockReturnValue('someObj'),
            statusText: 'someStatusText'
        })

        await expect(messageService.execute('somePath', 'GET', 'someToken', 'someData')).rejects.toBeTruthy();
        await expect(global.fetch).toBeCalled();
    })

    test('buildUrl method', ()=>{
        expect(MessageService.buildUrl('somePath')).toBe('https://affinidi-messages.dev.affinity-project.org/api/v1somePath');
    })

    afterEach(()=>{
        jest.restoreAllMocks()
    });
})