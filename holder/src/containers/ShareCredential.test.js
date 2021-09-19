import React from 'react';
import {act, render, waitFor} from '@testing-library/react';
import  ShareCredential from './ShareCredential';
import SdkService from '../utils/sdkService';
import {MessageService} from "../utils/messageService";
import userEvent from '@testing-library/user-event';


jest.mock('../utils/messageService');
jest.mock('../utils/sdkService');


const testProps = {
    userHasAuthenticated: jest.fn(),
    setShareRequestToken: jest.fn(),
    history: {
        push: jest.fn()
    },
    location: {
        search: '?vcURL=https://cloud-wallet-api.dev.affinity-project.org/api/v1/share/fbd7da2e0e8271d1e0efc9c934f3587bbf4f1b75e1b035f6f4e3ba4168f883f4?key=e07827abb2b83c2343b8e7519351b3e0b3dc284daacc67681a9cf0877d691a16&token=testtoken'
    },
}

describe('Test ShareCredential component', ()=>{

    describe('UI Tests', () => {

        beforeEach(()=>{
            window.sdk = new SdkService();
            window.alert = jest.fn();
            jest.spyOn(console, 'log').mockImplementation();
            jest.spyOn(SdkService.prototype, 'init').mockResolvedValue();
        });

        test('User who is logged in can see the credential he wants to share', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'familyName'
                    }
                },
                type: ['NameCredentialPersonV1']
            }

            const parseToken = {
                payload: {
                    interactionToken: {
                        callbackURL: "someUrl"
                    },
                    iss: "someIss"
                }
            }
        
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue({did: "someDid"});
            jest.spyOn(SdkService.prototype, 'createCredentialShareResponseToken').mockResolvedValue("someToken");
            jest.spyOn(SdkService.prototype, 'getCredentials').mockResolvedValue([testCredential]);
            jest.spyOn(SdkService.prototype, 'parseToken').mockReturnValue(parseToken)
            jest.spyOn(MessageService.prototype, 'send').mockResolvedValue('someMes');

            const { queryByText, queryByRole } = render(
                <ShareCredential
                    userHasAuthenticated={testProps.userHasAuthenticated}
                    setShareRequestToken={testProps.setShareRequestToken}
                    history={testProps.history}
                    location={testProps.location}
                />
            );

            await waitFor(()=>expect(window.sdk.init).toBeCalled());
            await waitFor(()=>expect(MessageService).toBeCalled());

            expect(queryByRole('heading', {level: 1, name: "Share Credentials"})).toBeTruthy();
            expect(queryByText('Please select which Credential you would like to share')).toBeTruthy();
            expect(queryByRole('columnheader', {name: '#'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Name'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Type'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Select'})).toBeTruthy();

            await waitFor(()=>expect(SdkService.prototype.getCredentials).toBeCalledWith('testtoken'));
            await waitFor(()=>expect(SdkService.prototype.parseToken).toBeCalledWith('testtoken'));

            expect(queryByRole('cell', {name: '1'})).toBeTruthy();
            expect(queryByRole('cell', {name: `${testCredential.credentialSubject.data.givenName} ${testCredential.credentialSubject.data.familyName}`})).toBeTruthy();
            expect(queryByRole('cell', {name: 'Name Document'})).toBeTruthy();
            expect(queryByRole('button', {name: 'Share'})).toBeTruthy();

            expect(queryByRole('cell', {name: 'Driving License'})).not.toBeTruthy();
            expect(queryByRole('cell', {name: testCredential.type})).not.toBeTruthy();
        });

        test('IDDocumentCredentialPersonV1 VC type should be shown as Driving License', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'familyName',
                        hasIDDocument: {
                            hasIDDocument: {
                                documentType: 'driving_license'
                            }
                        }
                    }
                },
                type: ['IDDocumentCredentialPersonV1']
            }

            const parseToken = {
                payload: {
                    interactionToken: {
                        callbackURL: "someUrl"
                    },
                    iss: "someIss"
                }
            }
        
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue({did: "someDid"});
            jest.spyOn(SdkService.prototype, 'createCredentialShareResponseToken').mockResolvedValue("someToken");
            jest.spyOn(SdkService.prototype, 'getCredentials').mockResolvedValue([testCredential]);
            jest.spyOn(SdkService.prototype, 'parseToken').mockReturnValue(parseToken)
            jest.spyOn(MessageService.prototype, 'send').mockResolvedValue('someMes');

            const { queryByRole } = render(
                <ShareCredential
                    userHasAuthenticated={testProps.userHasAuthenticated}
                    setShareRequestToken={testProps.setShareRequestToken}
                    history={testProps.history}
                    location={testProps.location}
                />
            );

            await waitFor(()=>expect(window.sdk.init).toBeCalled());
            await waitFor(()=>expect(MessageService).toBeCalled());

            await waitFor(()=>expect(SdkService.prototype.getCredentials).toBeCalledWith('testtoken'));
            await waitFor(()=>expect(SdkService.prototype.parseToken).toBeCalledWith('testtoken'));
            
            expect(queryByRole('cell', {name: 'Name Document'})).not.toBeTruthy();
            expect(queryByRole('cell', {name: 'Driving License'})).toBeTruthy();
            expect(queryByRole('cell', {name: testCredential.type})).not.toBeTruthy();
        })

        test('VC type that are not NameCredentialPersonV1 or IDDocumentCredentialPersonV1 should not be renamed on the UI', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'familyName',
                        hasIDDocument: {
                            hasIDDocument: {
                                documentType: 'driving_license'
                            }
                        }
                    }
                },
                type: ['other type']
            }

            const parseToken = {
                payload: {
                    interactionToken: {
                        callbackURL: "someUrl"
                    },
                    iss: "someIss"
                }
            }
        
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue({did: "someDid"});
            jest.spyOn(SdkService.prototype, 'createCredentialShareResponseToken').mockResolvedValue("someToken");
            jest.spyOn(SdkService.prototype, 'getCredentials').mockResolvedValue([testCredential]);
            jest.spyOn(SdkService.prototype, 'parseToken').mockReturnValue(parseToken)
            jest.spyOn(MessageService.prototype, 'send').mockResolvedValue('someMes');

            const { queryByRole } = render(
                <ShareCredential
                    userHasAuthenticated={testProps.userHasAuthenticated}
                    setShareRequestToken={testProps.setShareRequestToken}
                    history={testProps.history}
                    location={testProps.location}
                />
            );

            await waitFor(()=>expect(window.sdk.init).toBeCalled());
            await waitFor(()=>expect(MessageService).toBeCalled());

            await waitFor(()=>expect(SdkService.prototype.getCredentials).toBeCalledWith('testtoken'));
            await waitFor(()=>expect(SdkService.prototype.parseToken).toBeCalledWith('testtoken'));
            
            expect(queryByRole('cell', {name: 'Name Document'})).not.toBeTruthy();
            expect(queryByRole('cell', {name: 'Driving License'})).not.toBeTruthy();
            expect(queryByRole('cell', {name: testCredential.type})).toBeTruthy();
        })
    })

    describe('Functionality tests', () => {

        beforeEach(()=>{
            window.sdk = new SdkService();
            window.alert = jest.fn();
            jest.spyOn(console, 'log').mockImplementation();
            jest.spyOn(SdkService.prototype, 'init').mockResolvedValue();
        });

        test('User will be redirected if not login', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'familyName'
                    }
                },
                type: ['NameCredentialPersonV1']
            }
    
            const parseToken = {
                payload: {
                    interactionToken: {
                        callbackURL: "someUrl"
                    },
                    iss: "someIss"
                }
            }
            const error = new Error('Some Error');
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockRejectedValue(error)
            jest.spyOn(SdkService.prototype, 'createCredentialShareResponseToken').mockResolvedValue("someToken");
            jest.spyOn(SdkService.prototype, 'getCredentials').mockResolvedValue([testCredential]);
            jest.spyOn(SdkService.prototype, 'parseToken').mockReturnValue(parseToken);
            jest.spyOn(MessageService.prototype, 'send').mockResolvedValue('someMes');
            render(
                <ShareCredential
                    userHasAuthenticated={testProps.userHasAuthenticated}
                    setShareRequestToken={testProps.setShareRequestToken}
                    history={testProps.history}
                    location={testProps.location}
                />
            );
            await waitFor(()=>expect(window.sdk.init).toHaveBeenCalled());
            await waitFor(()=>expect(MessageService).toHaveBeenCalled());
            
            expect(SdkService.prototype.getDidAndCredentials).toBeCalled();
            expect(testProps.userHasAuthenticated).not.toBeCalledWith(true);
            expect(testProps.setShareRequestToken).toBeCalled();
            expect(window.alert).toBeCalledWith('Please login.');
            expect(testProps.history.push).toBeCalledWith('/login');
        });

        test('Clicking the share button will call messageService and send a message then route to /', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'familyName'
                    }
                },
                type: ['NameCredentialPersonV1']
            }
    
            const parseToken = {
                payload: {
                    interactionToken: {
                        callbackURL: "someUrl"
                    },
                    iss: "someIss"
                }
            }
        
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue({did: "someDid"});
            jest.spyOn(SdkService.prototype, 'createCredentialShareResponseToken').mockResolvedValue("someToken");
            jest.spyOn(SdkService.prototype, 'getCredentials').mockResolvedValue([testCredential]);
            jest.spyOn(SdkService.prototype, 'parseToken').mockReturnValue(parseToken);
            jest.spyOn(MessageService.prototype, 'send').mockResolvedValue('someMes');
    
            const { findByRole } = render(
                <ShareCredential
                    userHasAuthenticated={testProps.userHasAuthenticated}
                    setShareRequestToken={testProps.setShareRequestToken}
                    history={testProps.history}
                    location={testProps.location}
                />
            );
    
            const shareButton = await findByRole('button', {name: 'Share'});
            await act(async () => await userEvent.click(shareButton));
            
            await waitFor(()=>expect(SdkService.prototype.createCredentialShareResponseToken).toBeCalledWith('testtoken', [testCredential]));
            await waitFor(()=>expect(MessageService.prototype.send).toBeCalledWith('someIss', {token: 'someToken'}));
            expect(testProps.history.push).toBeCalledWith('/');
        });

        test('Will log the error if no credential is found', async () => {
            const parseToken = {
                payload: {
                    interactionToken: {
                        callbackURL: "someUrl"
                    },
                    iss: "someIss"
                }
            }
        
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockResolvedValue({did: "someDid"});
            jest.spyOn(SdkService.prototype, 'createCredentialShareResponseToken').mockResolvedValue("someToken");
            jest.spyOn(SdkService.prototype, 'getCredentials').mockResolvedValue([]);
            jest.spyOn(SdkService.prototype, 'parseToken').mockReturnValue(parseToken)
            jest.spyOn(MessageService.prototype, 'send').mockResolvedValue('someMes');
    
            render(
                <ShareCredential
                    userHasAuthenticated={testProps.userHasAuthenticated}
                    setShareRequestToken={testProps.setShareRequestToken}
                    history={testProps.history}
                    location={testProps.location}
                />
            );
    
            await waitFor(()=>expect(window.sdk.init).toBeCalled());
            await waitFor(()=>expect(MessageService).toBeCalled());
    
            await waitFor(()=>expect(SdkService.prototype.getCredentials).toBeCalledWith('testtoken'));
            const error = new Error('No credential found for this request!');
            await waitFor(()=>expect(console.log).toBeCalledWith(error));
        })
    })
})