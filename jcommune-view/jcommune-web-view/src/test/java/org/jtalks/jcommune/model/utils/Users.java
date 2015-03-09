/**
 * Copyright (C) 2011  JTalks.org Team
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.jtalks.jcommune.model.utils;

import org.jtalks.common.model.entity.Group;
import org.jtalks.common.service.security.SecurityContextHolderFacade;
import org.jtalks.jcommune.model.dao.GroupDao;
import org.jtalks.jcommune.model.dao.UserDao;
import org.jtalks.jcommune.model.entity.JCUser;
import org.jtalks.jcommune.service.nontransactional.EncryptionService;
import org.jtalks.jcommune.service.security.AdministrationGroup;
import org.jtalks.jcommune.service.security.PermissionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/**
 * @author Mikhail Stryzhonok
 */
public class Users {

    private static final Users INSTANCE = new Users();


    private Users() {
    }

    @Autowired
    private UserDao userDao;
    @Autowired
    private GroupDao groupDao;
    @Autowired
    private PermissionManager permissionManager;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private SecurityContextHolderFacade securityFacade;
    @Autowired
    private SessionAuthenticationStrategy sessionStrategy;
    @Autowired
    private EncryptionService encryptionService;

    private String defaultUserName = "SampleUser";
    private String defaultPassword = "pwd";

    protected static Users getInstance() {
        return INSTANCE;
    }

    public static PermissionGranter createAndSignIn() {
        JCUser user = new JCUser(INSTANCE.defaultUserName, "sample@example.com",
                INSTANCE.encryptionService.encryptPassword(INSTANCE.defaultPassword));
        user.setEnabled(true);
        Group group = INSTANCE.groupDao.getGroupByName(AdministrationGroup.USER.getName());
        user.addGroup(group);
        INSTANCE.userDao.saveOrUpdate(user);
        INSTANCE.userDao.flush();
        //We can't use same user object because it is attached to the current hibernate session and if we change
        //password it will be changed in database too
        JCUser toLogin =  new JCUser(INSTANCE.defaultUserName, "sample@example.com", INSTANCE.defaultPassword);
        signIn(toLogin);
        return new PermissionGranter(INSTANCE.permissionManager, group);
    }

    private static void signIn(JCUser user) {
        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        token.setDetails(user);
        Authentication auth = INSTANCE.authenticationManager.authenticate(token);
        INSTANCE.securityFacade.getContext().setAuthentication(auth);
        INSTANCE.sessionStrategy.onAuthentication(auth, new MockHttpServletRequest(), new MockHttpServletResponse());
    }
}
