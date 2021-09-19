import React, { useEffect, useState } from "react";
import { Table, Button } from "react-bootstrap";
import { useAsync, useAsyncFn } from "react-use";
import queryString from 'query-string'
import { MessageService } from "../utils/messageService";
import './ShareCredential.css';
import ShareVC from "./ShareVC";

function parseInfoFromToken(token)
{
  try {
    const { payload } = window.sdk.parseToken(token)
    const callbackURL = (payload.interactionToken || {}).callbackURL || undefined
    const requesterDid = payload.iss
    return { requesterDid, callbackURL }
  } catch (err) {
    console.log(err)
    return {}
  }
}

async function getCredentials(credentialShareRequestToken)
{
  const credentials = await window.sdk.getCredentials(credentialShareRequestToken)
  if (!Array.isArray(credentials) || credentials.length < 1) {
    const error = new Error('No credential found for this request!')
    throw error
  }
  return credentials
}

async function createCredentialShareResponseToken(credentialShareRequestToken, credentials, requesterDid, history)
{
  const credentialShareResponseToken = await window.sdk.createCredentialShareResponseToken(credentialShareRequestToken, credentials)
  if (requesterDid && credentialShareResponseToken) {
    const mes = await window.messageService.send(requesterDid, { token: credentialShareResponseToken })
    alert('Credential shared successfully!')
    history.push('/')
  }
  return { credentialShareResponseToken }
}

const ShareCredential = (props) =>
{
  const credentialShareRequestToken = queryString.parse(props.location.search).token || ''
  const { requesterDid } = parseInfoFromToken(credentialShareRequestToken)
  const [selected, setSelected] = useState('')

  useEffect(() =>
  {
    window.sdk.init().then(networkMember =>
    {
      window.messageService = new MessageService(networkMember)
    }).catch(console.error)
  }, [])

  const { loading: credentialsLoading, value: credentials, error: credentialsError } = useAsync(
    () => getCredentials(credentialShareRequestToken),
    [credentialShareRequestToken]
  )

  const [
    { loading: createVPLoading, value: presentation, error: createVPError },
    onCreateVP
  ] = useAsyncFn(
    (credentials) => createCredentialShareResponseToken(credentialShareRequestToken, credentials, requesterDid, props.history),
    [credentialShareRequestToken, credentials, requesterDid]
  );

  const searchKeyDetail = (credential) =>
  {
    const types = credential.type
    if (types[types.length - 1] === 'NameCredentialPersonV1') {
      return 'Name Document'
    }
    if (types[types.length - 1] === 'IDDocumentCredentialPersonV1') {
      if (credential.credentialSubject.data.hasIDDocument.hasIDDocument.documentType === 'driving_license') {
        return 'Driving License'
      }
    }
    return credential.type
  }

  useEffect(() =>
  {
    const checkLogin = async () =>
    {
      try {
        const { did } = await window.sdk.getDidAndCredentials();
        if (did) {
          props.userHasAuthenticated(true)
        }
      } catch (error) {
        if (queryString.parse(props.location.search).token) {
          props.setShareRequestToken(queryString.parse(props.location.search).token);
        }
        alert('Please login.')
        props.history.push('/login')
      }
    }
    try {
      checkLogin()
    } catch (error) {
      console.log(error)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className='ShareCred'>
      <div className='Form container'>
        <h1 className='Title'>Share Credentials</h1>
        <p>Please select which Credential you would like to share</p>
        <Table striped bordered hover size='sm'>
          <thead>
            <tr>
              <th>#</th>
              <th>Name</th>
              <th>Type</th>
              <th>Select</th>
            </tr>
          </thead>
          <tbody>
            {(credentials || []).map((credential, index) => (
              <tr key={index + 1}>
                <td>{index + 1}</td>
                <td>{credential.credentialSubject.data.givenName} {credential.credentialSubject.data.familyName}</td>
                <td>{searchKeyDetail(credential)}</td>
                <td>
                  <Button onClick={() => setSelected(credential)}>Share</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
        {selected &&
          <ShareVC selectedCard={selected} onClose={() => setSelected('')} setCred={(cred) => { onCreateVP([cred]) }} />
        }
      </div>
    </div>
  )
}

export default ShareCredential;