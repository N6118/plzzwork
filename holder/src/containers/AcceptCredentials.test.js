import React from 'react';
import {act, render, waitFor} from '@testing-library/react';
import  AcceptCredentials from './AcceptCredentials';
import SdkService from '../utils/sdkService';
import userEvent from '@testing-library/user-event';
import * as apiService from '../utils/apiService';


const testProps = {
    location: {
        search: '?vcURL=https://cloud-wallet-api.dev.affinity-project.org/api/v1/share/fbd7da2e0e8271d1e0efc9c934f3587bbf4f1b75e1b035f6f4e3ba4168f883f4?key=e07827abb2b83c2343b8e7519351b3e0b3dc284daacc67681a9cf0877d691a16'
    },
    setAcceptVCLink: jest.fn().mockImplementation(()=>{
        return {
            vcURL: 'testURL'
        }
    }),
    userHasAuthenticated: jest.fn().mockImplementation(),
    history: {
        push: jest.fn()
    }
}
jest.mock('./DisplayCredentials', ()=>() => <p>MockDisplay</p>);

describe('Test AcceptCredentials component', () => {

    beforeAll(() => {
        jest.spyOn(window, 'alert');
        window.sdk = new SdkService();
        jest.spyOn(console, 'log');
    })

    describe('UI tests', () => {
        test('AcceptCredentials component shows Verifiable Credential if Login and with a valid VC', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'testGivenFamilyName',
                        hasIDDocument: {
                            hasIDDocument: {
                                documentType: "testType"
                            }
                        }
                    },
                },
                httpStatusCode: 200
            }
            
            jest.spyOn(global, 'fetch').mockImplementation(() =>
                Promise.resolve({
                    json: () => Promise.resolve(testCredential),
                })
            );
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockImplementation(()=>{
                return Promise.resolve({did: 'did'});
            });
            const { queryByRole, queryByText } = render(<AcceptCredentials
                location={testProps.location}
                setAcceptVCLink={testProps.setAcceptVCLink}
                userHasAuthenticated={testProps.userHasAuthenticated}
                history={testProps.history}
            />);
            
            await waitFor(()=> {
                expect(SdkService.prototype.getDidAndCredentials).toHaveBeenCalled();
                expect(testProps.userHasAuthenticated).toBeCalled()
                expect(queryByRole('heading', {level: 1, name: "Approved Verifiable Credential"})).toBeTruthy();
                expect(queryByText('MockDisplay')).toBeTruthy();
                expect(queryByRole('button', {name: 'Save VC'})).toBeTruthy();
                expect(queryByRole('button', {name: 'Reject VC'})).toBeTruthy();
            });
            
        });

        test('AcceptCredentials component shows Verifiable Credential if not logged in', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'testGivenFamilyName',
                        hasIDDocument: {
                            hasIDDocument: {
                                documentType: "testType"
                            }
                        }
                    },
                },
                httpStatusCode: 200
            }
            
            jest.spyOn(global, 'fetch').mockImplementation(() =>
                Promise.resolve({
                    json: () => Promise.resolve(testCredential),
                })
            );
            const error = new Error('Some Error')
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockImplementation(()=>{
                throw error
            });
            render(<AcceptCredentials
                location={testProps.location}
                setAcceptVCLink={testProps.setAcceptVCLink}
                userHasAuthenticated={testProps.userHasAuthenticated}
                history={testProps.history}
            />);
            
            await waitFor(()=> {
                expect(testProps.setAcceptVCLink).toBeCalled();
                expect(window.alert).toBeCalledWith('Please login.')
                expect(testProps.history.push).toBeCalledWith('/login');
            });
        })

        test('AcceptCredentials component shows No Verifiable Credential Found if Logged in and with no VC', async () => {
            jest.spyOn(global, 'fetch').mockImplementation(() =>
                Promise.resolve({
                    json: () => Promise.resolve(null),
                })
            );
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockImplementation(()=>{
                return Promise.resolve({did: 'did'});
            });
            const { queryByRole } = render(<AcceptCredentials
                location={testProps.location}
                setAcceptVCLink={testProps.setAcceptVCLink}
                userHasAuthenticated={testProps.userHasAuthenticated}
                history={testProps.history}
            />);
            
            await waitFor(()=> {
                expect(SdkService.prototype.getDidAndCredentials).toHaveBeenCalled();
                expect(testProps.userHasAuthenticated).toBeCalled()
                expect(queryByRole('heading', {level: 3, name: "No Verifiable Credential found"})).toBeTruthy();
            });
            
        });
    });

    describe('Save credential functionality', () => {
        test('User can save VC', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'testGivenFamilyName',
                        hasIDDocument: {
                            hasIDDocument: {
                                documentType: "testType"
                            }
                        }
                    },
                },
                httpStatusCode: 200
            }
            
            global.fetch = jest.fn(() =>
                Promise.resolve({
                    json: () => Promise.resolve(testCredential),
                })
            );
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockImplementation(()=>{
                return Promise.resolve({did: 'did'});
            });
            apiService.storeSignedVCs = jest.fn().mockImplementation(()=>{
                return Promise.resolve({credentialIds: ["somecredential"]})
            })
            
            const { findByRole } = render(<AcceptCredentials
                location={testProps.location}
                setAcceptVCLink={testProps.setAcceptVCLink}
                userHasAuthenticated={testProps.userHasAuthenticated}
                history={testProps.history}
            />);

            const saveVCButton = await findByRole('button', {name: 'Save VC'});
            await act(async () => {
                await userEvent.click(saveVCButton);
            })
            
            await waitFor(()=>{
                expect(apiService.storeSignedVCs).toBeCalled();
                
                expect(testProps.setAcceptVCLink).toBeCalled();
                expect(testProps.history.push).toBeCalledWith('/')
            })
            
        });

        test('alert will show if storeSignedVC method throws an error', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'testGivenFamilyName',
                        hasIDDocument: {
                            hasIDDocument: {
                                documentType: "testType"
                            }
                        }
                    },
                },
                httpStatusCode: 200
            }
            
            global.fetch = jest.fn(() =>
                Promise.resolve({
                    json: () => Promise.resolve(testCredential),
                })
            );
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockImplementation(()=>{
                return Promise.resolve({did: 'did'});
            });
            const error = new Error('Some Error')
            apiService.storeSignedVCs = jest.fn().mockImplementation(()=>{
                throw error
            })
            
            const { findByRole } = render(<AcceptCredentials
                location={testProps.location}
                setAcceptVCLink={testProps.setAcceptVCLink}
                userHasAuthenticated={testProps.userHasAuthenticated}
                history={testProps.history}
            />);

            const saveVCButton = await findByRole('button', {name: 'Save VC'});
            await act(async () => {
                await userEvent.click(saveVCButton);
            })
            
            await waitFor(()=>{
                expect(apiService.storeSignedVCs).toBeCalled();
                expect(console.log).toBeCalledWith(error)
            })
        });
    });

    describe('Reject credential functionality', () => {
        test('User can reject VC and is being route to /', async () => {
            const testCredential = {
                credentialSubject: {
                    data: {
                        givenName: 'testGivenName',
                        familyName: 'testGivenFamilyName',
                        hasIDDocument: {
                            hasIDDocument: {
                                documentType: "testType"
                            }
                        }
                    },
                },
                httpStatusCode: 200
            }
            
            global.fetch = jest.fn(() =>
                Promise.resolve({
                    json: () => Promise.resolve(testCredential),
                })
            );
            jest.spyOn(SdkService.prototype, 'getDidAndCredentials').mockImplementation(()=>{
                return Promise.resolve({did: 'did'});
            });
            
            const { findByRole } = render(<AcceptCredentials
                location={testProps.location}
                setAcceptVCLink={testProps.setAcceptVCLink}
                userHasAuthenticated={testProps.userHasAuthenticated}
                history={testProps.history}
            />);

            const rejectVCButton = await findByRole('button', {name: 'Reject VC'});
            await act(async () => {
                await userEvent.click(rejectVCButton);
            })
            
            await waitFor(()=>{
                expect(testProps.history.push).toBeCalledWith('/');
            })
        });
    })


})