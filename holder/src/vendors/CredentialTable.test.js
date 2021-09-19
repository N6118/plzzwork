import React from 'react';
import {render} from '@testing-library/react';
import CredentialTable from './CredentialTable'


describe('Test CredentialTable', () => {
    describe('UI Tests', () => {
        test('UI can render VC', () => {
            const testCredential = {
                credential: {
                    credentialSubject: {
                        data: {
                            givenName: 'testGivenName',
                            familyName: 'familyName',
                            hasIDDocument: {
                                hasIDDocument: {
                                    documentType: 'driving_license',
                                    idClass: JSON.stringify({email: 'someEmail'})
                                }
                            }
                        }
                    },
                    type: ['IDDocumentCredentialPersonV1']
                }
            }
            const { queryByRole } = render(<CredentialTable
                credentials = {[testCredential]}
            />)
            expect(queryByRole('columnheader', {name: 'Index'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Given Name'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Family Name'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Email'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'VC Type'})).toBeTruthy();
            expect(queryByRole('rowheader', {name: '1'})).toBeTruthy();
            expect(queryByRole('cell', {name: 'testGivenName'})).toBeTruthy();
            expect(queryByRole('cell', {name: 'familyName'})).toBeTruthy();
            expect(queryByRole('cell', {name: 'someEmail'})).toBeTruthy();
            expect(queryByRole('cell', {name: 'driving_license'})).toBeTruthy();
        })

        test('VC has no email and document type if Credential does not have a hasIDDocument property', ()=>{
            const testCredential = {
                credential: {
                    credentialSubject: {
                        data: {
                            givenName: 'testGivenName',
                            familyName: 'familyName',
                            hasIDDocument: null
                        }
                    },
                    type: ['IDDocumentCredentialPersonV1']
                }
            }
            const { queryByRole } = render(<CredentialTable
                credentials = {[testCredential]}
            />)
            expect(queryByRole('columnheader', {name: 'Index'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Given Name'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Family Name'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'Email'})).toBeTruthy();
            expect(queryByRole('columnheader', {name: 'VC Type'})).toBeTruthy();
            expect(queryByRole('rowheader', {name: '1'})).toBeTruthy();
            expect(queryByRole('cell', {name: 'testGivenName'})).toBeTruthy();
            expect(queryByRole('cell', {name: 'familyName'})).toBeTruthy();
            expect(queryByRole('cell', {name: 'someEmail'})).not.toBeTruthy();
            expect(queryByRole('cell', {name: 'driving_license'})).not.toBeTruthy();
        })
    })
})