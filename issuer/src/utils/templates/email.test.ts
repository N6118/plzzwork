import {SES} from 'aws-sdk';
import {sendEmail} from './email'


jest.mock('../config', ()=>({
    accessKeyId: 'someAccessKeyId',
    secretAccessKey: 'someSecretAccessKey',
    wallet_url: 'someWalletUrl'
}))

jest.mock('aws-sdk', ()=>{
    return {
        SES: jest.fn()
    }
})


describe('Test email', ()=>{
    test('sendEmail Function send email successfully', ()=>{
        SES.prototype.sendRawEmail = jest.fn().mockReturnValue('someEmail')
        sendEmail('someQrCode', 'someSharingUrl', 'someReceiverEmail');
        expect(SES).toBeCalledWith(
            {accessKeyId: 'someAccessKeyId', apiVersion: '2020-12-01', region: 'us-east-1', secretAccessKey: 'someSecretAccessKey'}
        )
        expect(SES.prototype.sendRawEmail).toHaveReturnedWith('someEmail')
    })
})