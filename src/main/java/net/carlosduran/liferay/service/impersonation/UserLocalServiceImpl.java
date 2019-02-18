package net.carlosduran.liferay.service.impersonation;

import java.util.Map;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.GetterUtil;
import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.model.User;
import com.liferay.portal.security.auth.Authenticator;
import com.liferay.portal.service.RoleLocalServiceUtil;
import com.liferay.portal.service.UserLocalService;
import com.liferay.portal.service.UserLocalServiceWrapper;

public class UserLocalServiceImpl extends UserLocalServiceWrapper {
	
	private static final String DEFAULT_IMPERSONATION_ROLE_NAME = "ImpersonationUser";
	private static final String USER_ID = "userId";
	private static final String PROPERTY_IMPERSONATION_ROLE = "impersonation-role";
	private static Log logger = LogFactoryUtil.getLog(UserLocalServiceImpl.class);

	public UserLocalServiceImpl(UserLocalService userLocalService) {
		super(userLocalService);
	}

	@Override
	public int authenticateByScreenName(long companyId, String screenName, String password,
			Map<String, String[]> headerMap, Map<String, String[]> parameterMap, Map<String, Object> resultsMap)
			throws PortalException, SystemException {
		
		User impersonationUser = null;
		
		if(screenName.indexOf(StringPool.POUND) > -1) {
			String[] impersonationComposition = screenName.split(StringPool.POUND);
			screenName = impersonationComposition[0];
			try {
				impersonationUser = getUserByScreenName(companyId, impersonationComposition[1]);
			} catch (Exception ex) {
				logger.warn("Cannot get user to impersonate: " + ex.getMessage());
			}
		}
		
		int authenticateResult = super.authenticateByScreenName(companyId, screenName, password, headerMap, parameterMap, resultsMap);
		
		if(!Validator.isNull(impersonationUser) && authenticateResult == Authenticator.SUCCESS) {
			logger.info("User " + screenName.toUpperCase() + " wants to impersonate " + impersonationUser.getScreenName());
			long userId = GetterUtil.getLong(resultsMap.get(USER_ID));
			if(canImpersonate(companyId, userId)) {
				resultsMap.put(USER_ID, impersonationUser.getUserId());
			}
		}
		
		return authenticateResult;
	}
	
	private static boolean canImpersonate(long companyId, long userId) {
		
		String impersonationRoleName = getImpersonationRoleName();
		
		try {			
			return RoleLocalServiceUtil.hasUserRole(userId, companyId, impersonationRoleName, Boolean.TRUE);
		} catch (Exception ex) {
			logger.error(ex.getClass().getName() + ": " + ex.getMessage());
		}
		
		return false;
	}

	private static String getImpersonationRoleName() {
		String impersonationRoleName = GetterUtil.getString(PropsUtil.get(PROPERTY_IMPERSONATION_ROLE));
		
		if (!Validator.isBlank(impersonationRoleName)) {
			logger.debug("Impersonation role is not defined (impersonation-role property). Using default");
			impersonationRoleName = DEFAULT_IMPERSONATION_ROLE_NAME;
		}
		return impersonationRoleName;
	}

}
