package org.hasp.server.support;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.jackson2.SecurityJackson2Modules;

public class CustomJackson2Module extends SimpleModule {

    public CustomJackson2Module() {
        super(CustomJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
        context.setMixInAnnotations(CustomUser.class, CustomUserMixin.class);
    }

}
