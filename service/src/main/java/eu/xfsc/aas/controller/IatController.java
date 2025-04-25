package eu.xfsc.aas.controller;

import eu.xfsc.aas.generated.controller.IatControllerApi;
import eu.xfsc.aas.generated.controller.IatControllerApiDelegate;
import eu.xfsc.aas.generated.model.AccessRequestDto;
import eu.xfsc.aas.generated.model.AccessResponseDto;
import eu.xfsc.aas.service.SsiIatService;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class IatController implements IatControllerApiDelegate {

    private final SsiIatService iatService;

    /**
     * GET /clients/iat/requests/{request_id} : Get IAT provisioning request details
     *
     * @param requestId Request identifier (required)
     * @return Success (status code 200)
     *         or Invalid input data (status code 400)
     *         or Unauthorized (status code 401)
     *         or Request with selected id was not found (status code 404)
     *         or Internal Server Error (status code 500)
     * @see IatControllerApi#getAccessRequest
     */
    @Override
    public ResponseEntity<AccessResponseDto> postAccessRequest(AccessRequestDto accessRequestDto) {

        return ResponseEntity.ok(iatService.evaluateIatProofInvitation(accessRequestDto));
    }

    /**
     * POST /clients/iat/requests : Create IAT provisioning request
     *
     * @param accessRequestDto Request data (required)
     * @return Success (status code 201)
     *         or Invalid input data (status code 400)
     *         or Unauthorized (status code 401)
     *         or Internal Server Error (status code 500)
     * @see IatControllerApi#postAccessRequest
     */
    @Override
    public ResponseEntity<AccessResponseDto> getAccessRequest(String requestId) {
    	
        return ResponseEntity.ok(iatService.evaluateIatProofResult(requestId));
    }

}

