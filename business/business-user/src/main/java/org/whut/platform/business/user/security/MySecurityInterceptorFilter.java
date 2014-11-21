package org.whut.platform.business.user.security;

/**
  AbstractSecurityInterceptor确保security interceptor得到正确的启动配置，它将同样实现的对安全对象的操作有:
 1.从SecurityContextHolder对象中获得Authentication对象
 2.依靠对ObjectDefinitionSource查询获得的安全对象访问来判断请求涉及的是一个受保护的对象或是一个公用的对象 .

 如果对象是受保护的，即对于安全对象有一个ConfigAttributeDefinition ，则进行如下流程:
 1.如果Authentication.isAuthenticated()方法返回false，或者alwaysReauthenticate为true，则通过配置的AuthenticationManager对
 请求进行认证。如果认证成功，将返回的Authentication对象放回SecurityContextHolder中。
 2.通过配置的AccessDecisionManager对请求授权
 3.通过RanAsManager处理所有的run-as替换
 4.将控制传递给实际的子类继续执行。为了确保AbstractSecurityInterceptor被重新调用，当子类完成处理后一个InterceptorStatusToken将被返回。
 具体的子类将通过afterInvocation(InterceptorStatusToken, Object) 方法重新调用AbstractSecurityInterceptor。
 5.如果RunAsManager替换了Authentication对象，则为该对象返回SecurityContextHolder。
 6.如果一个AfterInvocationManager被定义，那么执行它，并允许其替换应返回给调用者的对象。
 对于公共的对象，即对此安全对象没有对应的ConfigAttributeDefinition:
 具体的子类在安全对象被执行后返回的InterceptorStatusToken随后将传回AbstractSecurityInterceptor，Abstract
 SecurityInterceptor在afterInvocation(InterceptorStatusToken,Object)方法被调用后将不继续进行其它动作。
 之后控制重新返回给实际子类，子类将返回结果或异常给原始的调用者
 */

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

import javax.servlet.*;
import java.io.IOException;

public class MySecurityInterceptorFilter extends AbstractSecurityInterceptor implements
        Filter {
    // 与applicationContext-security.xml里的myFilter的属性securityMetadataSource对应，
    // 其他的两个组件，已经在AbstractSecurityInterceptor定义
    private FilterInvocationSecurityMetadataSource securityMetadataSource;

    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        invoke(fi);
    }

    private void invoke(FilterInvocation fi) throws IOException,
            ServletException {
        // object为FilterInvocation对象
        // super.beforeInvocation(fi);//源码
        // 1.获取请求资源的权限
        //执行 Collection<ConfigAttribute> attributes = securityMetadataSource.getAttributes(fi);在 AbstractSecurityInterceptor中调用 其实现在MySecurityMetadataSource
        // 2.是否拥有权限
        // this.accessDecisionManager.decide(authenticated, fi, attributes);
        // this.accessDecisionManager.decide(authenticated, fi, attributes);
        InterceptorStatusToken token = super.beforeInvocation(fi);
        try {
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } finally {
            super.afterInvocation(token, null);
        }
    }

    public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
        return securityMetadataSource;
    }

    public void setSecurityMetadataSource(
            FilterInvocationSecurityMetadataSource securityMetadataSource) {
        this.securityMetadataSource = securityMetadataSource;
    }

    public void init(FilterConfig arg0) throws ServletException {
        // TODO Auto-generated method stub
    }

    public void destroy() {
        // TODO Auto-generated method stub

    }

    @Override
    public Class<? extends Object> getSecureObjectClass() {
        //下面的MyAccessDecisionManager的supports方面必须放回true,否则会提醒类型错误
        return FilterInvocation.class;
    }
}
