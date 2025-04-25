## Integration with TSA

AAS must communicate with Trust Services API (LOT4 implementation, TSA) in order to evaluate some specific policies for particular clients. According to TSA specification the request to policy evaluation endpoint is:

_POST /{repo}/policies/{group}/{policyname}/{version}/{action}_

- repo, group: not clear, what they are. TSA spec has a sample value: aisbl.
- policyname: one of "GetLoginProofInvitation", "GetLoginProofResult", "GetIatProofInvitation", "GetIatProofResult"
- version: also will take it from AAS config. Let's use value 1 for now.
- action: "evaluation"
- Input: some JSON Object
- Output: some JSON Object

Policy evaluation can be asynchronous. Input and Output objects depend on the Policy evaluated.

Policies evaluated from AAS
1. GetLoginProofInvitation Policy

   Scenario: IDM.AA QR Code Generation, IDM.AA.00001 Session handling and scope elevation

   Description: This policy MUST respond to the AA request containing the scope and namespace for the authorization request. It returns the according presentationID and link from the OCM.

   Problem: AAS will never see DID, so we can't pass it to TSA. But we can start DID invitation without sub, just to get a presentationID and link back..

2. GetLoginProofResult Policy

   Scenario: IDM.AA.00002 Login State Background Polling IDM.AA.00002 Session handling and scope elevation

   Description: This policy MUST provide a result to the AA request initiated with GetLoginProofInvitation provided presentationID. The result shall be a flattened list of claims related to the requested scopes of identity content (see IDM.TSA.00061 Trusted Identity Information)  

3. GetIatProofInvitation Policy

   Scenario: IDM.AA Policy based authorization

   Description: This policy MUST evaluate whether a client is allowed to obtain an Initial Access Token. It will request an appropriate invitation from the corresponding OCM.

4. GetIatProofResult Policy

   Scenario: IDM.AA Policy based authorization

   Description: This policy endpoint MUST return the IAT Proof Invitation result to the AA based on the according policy.


