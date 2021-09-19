import React from 'react';
import { render, waitFor} from '@testing-library/react';
import SdkService from '../utils/sdkService';
import Home from './Home';


const testProps = {
    history: {
        push: jest.fn('/')
    },
    userHasAuthenticated: jest.fn(),
    location: {
        search: '?vcURL=https://cloud-wallet-api.dev.affinity-project.org/api/v1/share/fbd7da2e0e8271d1e0efc9c934f3587bbf4f1b75e1b035f6f4e3ba4168f883f4?key=e07827abb2b83c2343b8e7519351b3e0b3dc284daacc67681a9cf0877d691a16&token=testtoken'
    },
}

const testCredential = {
    credentialSubject: {
        data: {
            givenName: 'testGivenName',
            familyName: 'familyName'
        }
    },
    type: ['NameCredentialPersonV1']
}

jest.mock('../vendors/CredentialTable', ()=>()=><div>Credential Table</div>)

describe('Test home component', () => {

    describe('UI tests', () => {
        beforeEach(()=>{
            window.sdk = new SdkService();
        })

        test('User is logged in and can see his credentials in his wallet', async ()=>{
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue({did: 'someDid', credentials: [testCredential]});
            const { getByRole, queryByText } = render(
                <Home 
                    userHasAuthenticated = {testProps.userHasAuthenticated}
                    history = {testProps.history}
                    location = {testProps.location}
                    isAuthenticated = {true}
                />
            )
            
            await waitFor(()=>expect(SdkService.prototype.getDidAndCredentials).toBeCalled());
            expect(testProps.userHasAuthenticated).not.toBeCalledWith(false);
            expect(testProps.history.push).not.toBeCalledWith('/login');
            expect(getByRole('heading', {level: 1, name: "Wallet"})).toBeTruthy();
            await waitFor(()=>expect(queryByText('Credential Table')).toBeTruthy());
            await waitFor(()=>expect(queryByText('You have no credentials.')).not.toBeTruthy());
        })

        test('User is logged in will not see any credentials if he has no VC', async () =>{
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue({did: 'someDid', credentials: []});
            const { getByRole, queryByText } = render(
                <Home 
                    userHasAuthenticated = {testProps.userHasAuthenticated}
                    history = {testProps.history}
                    location = {testProps.location}
                    isAuthenticated = {true}
                />
            )
            
            await waitFor(()=>expect(SdkService.prototype.getDidAndCredentials).toBeCalled());
            expect(testProps.userHasAuthenticated).not.toBeCalledWith(false);
            expect(testProps.history.push).not.toBeCalledWith('/login');
            expect(getByRole('heading', {level: 1, name: "Wallet"})).toBeTruthy();
            await waitFor(()=>expect(queryByText('Credential Table')).not.toBeTruthy());
            await waitFor(()=>expect(queryByText('You have no credentials.')).toBeTruthy());
        })
    })

    describe('Functionality tests', () => {
        test('User if not logged in will route back home', async () => {
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue(null);
            render(
                <Home 
                    userHasAuthenticated = {testProps.userHasAuthenticated}
                    history = {testProps.history}
                    location = {testProps.location}
                    isAuthenticated = {true}
                />
            )

            await waitFor(()=>expect(SdkService.prototype.getDidAndCredentials).toBeCalled());
            expect(testProps.userHasAuthenticated).toBeCalledWith(false);
            expect(testProps.history.push).toBeCalledWith('/login');
        })
    })
})
