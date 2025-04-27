package org.hasp.server.repository.remote;

import lombok.RequiredArgsConstructor;
import org.hasp.server.dto.TransferClient;
import org.hasp.server.repository.core.TransferClientRepository;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class RemoteTransferClientRepository implements TransferClientRepository {

    @Override
    public void save(TransferClient client) {

    }

    @Override
    public TransferClient findById(String id) {
        return null;
    }

    @Override
    public TransferClient findByClientId(String clientId) {
        return null;
    }
}
