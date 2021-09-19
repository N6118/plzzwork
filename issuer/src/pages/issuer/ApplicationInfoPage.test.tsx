import React from 'react'
import {render, act, waitFor} from '@testing-library/react';
import userEvent from '@testing-library/user-event'
import ApplicationInfoPage from './ApplicationInfoPage'
import {MemoryRouter} from 'react-router-dom';
import { sendEmail } from 'utils/templates/email';
import ApiService from 'utils/apiService';
import {signedDrivingLicenseVC, unsignedDrivingLicenseVC, } from 'utils/vc-data-examples/drivinglicense';
import { SignCredentialOutput, VCBuildUnsignedOutput, SaveCredentialOutput } from 'utils/apis';
import { routes } from 'constants/routes';

const unSignedVCOuput: VCBuildUnsignedOutput = {unsignedVC: unsignedDrivingLicenseVC};
const signedVCOutput: SignCredentialOutput = {signedCredential: signedDrivingLicenseVC};
const saveVCOutput: SaveCredentialOutput = {credentialIds: ['someId']}
const shareVCOuput = {
    qrCode: 'someQrCode',
    sharingUrl: 'someSharingUrl'
}

jest.mock('firebase', () => {
    return {
        initializeApp: jest.fn().mockImplementation(() => {}),
        firestore: jest.fn().mockImplementation(() => {
            return {
                collection: jest.fn().mockImplementation(() => {
                    return {
                        add: jest.fn(),
                        doc: jest.fn().mockReturnValue({
                            delete: jest.fn()
                        })
                    }
                })
            }
        })       
    }
});

jest.mock('utils/templates/email', ()=>({
    sendEmail: jest.fn()
}));

const mockHistoryPush = jest.fn();

jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    useHistory: () => ({
      push: mockHistoryPush,
    }),
  }));

describe('Test ApplicationInfoPage', ()=>{
    test('UI will render', ()=>{
        const testProps = {
            location: {
                state: {
                    state: {
                        username: 'someUser',
                        payload: {
                            givenName: 'someGivenName',
                            familyName: 'someFamilyName',
                            holderDid: 'someHolderDid',
                            idClass: '{"country": "someCountry", "drivingClass": "someDrivingClass", "email":"someEmail", "issuerOrganization": "someIssuerOrganization"}',
                            issueDate: 'someDate',
                        },
                        docID: 'ewiofjo2o3fj2f',
                        approved: false,
                        applicationID: 'k2r3io23f29',
                    }
                }
            },
        
        }

        const {queryByRole, queryByText } = render(<MemoryRouter><ApplicationInfoPage 
            location = {testProps.location}
        />
        </MemoryRouter>)

        expect(queryByRole('heading', {name: 'Application ID: k2r3io23f29', level: 3})).toBeTruthy();
        expect(queryByText('Given Name:')).toBeTruthy();
        expect(queryByText('someGivenName')).toBeTruthy();
        expect(queryByText('Family Name:')).toBeTruthy();
        expect(queryByText('someFamilyName')).toBeTruthy();
        expect(queryByText('Date of Issuance:')).toBeTruthy();
        expect(queryByText('someDate')).toBeTruthy();
        expect(queryByText('Issuer Organisation:')).toBeTruthy();
        expect(queryByText('someIssuerOrganization')).toBeTruthy();
        expect(queryByText('Country of Issuance:')).toBeTruthy();
        expect(queryByText('someCountry')).toBeTruthy();
        expect(queryByText('Driving Class:')).toBeTruthy();
        expect(queryByText('someDrivingClass')).toBeTruthy();
        expect(queryByRole('button', {name: 'View Proof of Document'})).toBeTruthy();
        expect(queryByRole('button', {name: 'Approve'})).toBeTruthy();
        expect(queryByRole('button', {name: 'Reject'})).toBeTruthy();
    })

    test('user can approve document', async ()=>{
        const testProps = {
            location: {
                state: {
                    state: {
                        username: 'someUser',
                        payload: {
                            givenName: 'someGivenName',
                            familyName: 'someFamilyName',
                            holderDid: 'someHolderDid',
                            idClass: '{"country": "someCountry", "drivingClass": "someDrivingClass", "email":"someEmail", "issuerOrganization": "someIssuerOrganization"}',
                            issueDate: 'someDate',
                        },
                        docID: 'ewiofjo2o3fj2f',
                        approved: false,
                        applicationID: 'k2r3io23f29',
                    }
                }
            },
        
        }

        const { getByRole } = render(<MemoryRouter><ApplicationInfoPage 
            location = {testProps.location}
        />
        </MemoryRouter>)

        jest.spyOn(ApiService, 'issueUnsignedVC').mockResolvedValue(unSignedVCOuput);
        jest.spyOn(ApiService, 'signVC').mockResolvedValue(signedVCOutput);
        jest.spyOn(ApiService, 'storeSignedVCs').mockResolvedValue(saveVCOutput);
        jest.spyOn(ApiService, 'shareCredentials').mockResolvedValue(shareVCOuput);
        jest.spyOn(ApiService, 'alertWithBrowserConsole');
        jest.spyOn(window, 'alert');

        const approveButton = getByRole('button', {name: 'Approve'});

        await act(async ()=>{
            await userEvent.click(approveButton);
        })

        await waitFor(()=>expect(ApiService.issueUnsignedVC).toBeCalled());
        await waitFor(()=>expect(ApiService.signVC).toBeCalled());
        await waitFor(()=>expect(ApiService.storeSignedVCs).toBeCalled());
        await waitFor(()=>expect(ApiService.shareCredentials).toBeCalled());
        expect(sendEmail).toBeCalledWith(shareVCOuput.qrCode, shareVCOuput.sharingUrl, 'someEmail');

        expect(mockHistoryPush).toBeCalledWith(routes.ISSUER);
        expect(window.alert).toBeCalledWith('Application has been approved and have alerted the applicant.')
        expect(ApiService.alertWithBrowserConsole).not.toBeCalled();
    })

    test('user cannot approve document', async ()=>{
        const testProps = {
            location: {
                state: {
                    state: {
                        username: 'someUser',
                        payload: {
                            givenName: 'someGivenName',
                            familyName: 'someFamilyName',
                            holderDid: 'someHolderDid',
                            idClass: '{"country": "someCountry", "drivingClass": "someDrivingClass", "email":"someEmail", "issuerOrganization": "someIssuerOrganization"}',
                            issueDate: 'someDate',
                        },
                        docID: 'ewiofjo2o3fj2f',
                        approved: true,
                        applicationID: 'k2r3io23f29',
                    }
                }
            },
        
        }

        const {queryByRole, queryByText } = render(<MemoryRouter><ApplicationInfoPage 
            location = {testProps.location}
        />
        </MemoryRouter>)

        expect(queryByRole('heading', {name: 'Application ID: k2r3io23f29', level: 3})).toBeTruthy();
        expect(queryByText('Given Name:')).toBeTruthy();
        expect(queryByText('someGivenName')).toBeTruthy();
        expect(queryByText('Family Name:')).toBeTruthy();
        expect(queryByText('someFamilyName')).toBeTruthy();
        expect(queryByText('Date of Issuance:')).toBeTruthy();
        expect(queryByText('someDate')).toBeTruthy();
        expect(queryByText('Issuer Organisation:')).toBeTruthy();
        expect(queryByText('someIssuerOrganization')).toBeTruthy();
        expect(queryByText('Country of Issuance:')).toBeTruthy();
        expect(queryByText('someCountry')).toBeTruthy();
        expect(queryByText('Driving Class:')).toBeTruthy();
        expect(queryByText('someDrivingClass')).toBeTruthy();
        expect(queryByRole('button', {name: 'View Proof of Document'})).toBeTruthy();
        expect(queryByRole('button', {name: 'Approve'})).not.toBeTruthy();
        expect(queryByRole('button', {name: 'Reject'})).not.toBeTruthy();
    })

    test('Will throw error if there is an error', async ()=>{
        const testProps = {
            location: {
                state: {
                    state: {
                        username: 'someUser',
                        payload: {
                            givenName: 'someGivenName',
                            familyName: 'someFamilyName',
                            holderDid: 'someHolderDid',
                            idClass: '{"country": "someCountry", "drivingClass": "someDrivingClass", "email":"someEmail", "issuerOrganization": "someIssuerOrganization"}',
                            issueDate: 'someDate',
                        },
                        docID: 'ewiofjo2o3fj2f',
                        approved: false,
                        applicationID: 'k2r3io23f29',
                    }
                }
            },
        
        }

        const { getByRole } = render(<MemoryRouter><ApplicationInfoPage 
            location = {testProps.location}
        />
        </MemoryRouter>)

        const error = new Error("someErrorMessage")
        jest.spyOn(ApiService, 'issueUnsignedVC').mockRejectedValue(error)
        jest.spyOn(ApiService, 'signVC').mockResolvedValue(signedVCOutput);
        jest.spyOn(ApiService, 'storeSignedVCs').mockResolvedValue(saveVCOutput);
        jest.spyOn(ApiService, 'shareCredentials').mockResolvedValue(shareVCOuput);
        jest.spyOn(ApiService, 'alertWithBrowserConsole');
        jest.spyOn(window, 'alert');

        const approveButton = getByRole('button', {name: 'Approve'});

        await act(async ()=>{
            await userEvent.click(approveButton);
        })

        await waitFor(()=>expect(ApiService.issueUnsignedVC).toBeCalled());
        await waitFor(()=>expect(ApiService.signVC).not.toBeCalled());
        await waitFor(()=>expect(ApiService.storeSignedVCs).not.toBeCalled());
        await waitFor(()=>expect(ApiService.shareCredentials).not.toBeCalled());
        expect(sendEmail).not.toBeCalledWith(shareVCOuput.qrCode, shareVCOuput.sharingUrl, 'someEmail');

        expect(mockHistoryPush).not.toBeCalledWith(routes.ISSUER);
        expect(window.alert).not.toBeCalledWith('Application has been approved and have alerted the applicant.')
        expect(ApiService.alertWithBrowserConsole).toBeCalledWith(error.message);
    })
})