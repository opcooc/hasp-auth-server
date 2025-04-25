package org.hasp.server.repository.core;

import org.hasp.server.dto.TransferClient;

public interface TransferClientRepository {

    void save(TransferClient client);

    TransferClient findById(String id);

    TransferClient findByClientId(String clientId);
}
