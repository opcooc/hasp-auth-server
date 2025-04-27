package org.hasp.server.repository.remote;

import lombok.RequiredArgsConstructor;
import org.hasp.server.dto.TransferUser;
import org.hasp.server.repository.core.TransferUserRepository;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class RemoteTransferUserRepository implements TransferUserRepository {

    @Override
    public TransferUser load(String username, String source) {
        return null;
    }

    @Override
    public void register(Map<String, Object> map) {
    }

    @Override
    public void updatePassword(String userId, String newPassword) {
    }

}
