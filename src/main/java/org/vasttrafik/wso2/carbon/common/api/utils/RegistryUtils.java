package org.vasttrafik.wso2.carbon.common.api.utils;

import org.wso2.carbon.registry.ws.stub.WSRegistryServiceStub;

import javax.activation.DataHandler;
import javax.ws.rs.NotFoundException;

/**
 * @author Daniel Oskarsson <daniel.oskarsson@gmail.com>
 */
public final class RegistryUtils {

    private static final WSRegistryServiceStub registryStub = ClientUtils.getWSRegistryServiceStub();

    public static Object getContent(final String path) {
        try {
            ClientUtils.authenticateIfNeeded(registryStub._getServiceClient());
            final DataHandler datahandler = registryStub.getContent(path);
            return datahandler.getContent();
        } catch (Exception e) {
            throw new NotFoundException();
        }
    }

}
