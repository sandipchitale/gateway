package com.example.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

}

    // @Component
    // public static class CLIR implements CommandLineRunner {

    // 	@Autowired
    // 	@Qualifier("springSecurityFilterChain")
    // 	private Filter springSecurityFilterChain;

    // 	@Override
    // 	public void run(String... args) throws Exception {
    // 		FilterChainProxy filterChainProxy = (FilterChainProxy) springSecurityFilterChain;

    // 		List<SecurityFilterChain> list = filterChainProxy.getFilterChains();
    // 		list.stream()
    // 			.map(chain -> (DefaultSecurityFilterChain) chain)
    // 			.peek(chain -> System.out.println("Request Matcher --------------------------------------------"))
    // 			.peek(chain -> System.out.println(chain.getRequestMatcher()))
    // 			.peek(chain -> System.out.println("Filters -------------------------------------"))
    // 			.flatMap(chain -> chain.getFilters().stream())
    // 			.forEach(filter -> System.out.println(filter.getClass()));
    // 	}
    // }

    // public class DumpFilters extends OncePerRequestFilter {
    // 	@Override
    // 	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
    // 			FilterChain filterChain) throws ServletException, IOException {
    // 		if (filterChain instanceof ApplicationFilterChain) {
    // 			ApplicationFilterChain applicationFilterChain = (ApplicationFilterChain) filterChain;
    // 			try {
    // 				Field filters = applicationFilterChain.getClass().getDeclaredField("filters");
    // 				filters.setAccessible(true);
    // 				ApplicationFilterConfig[] filterConfigs = (ApplicationFilterConfig[]) filters.get(applicationFilterChain);
    // 				for (ApplicationFilterConfig applicationFilterConfig : filterConfigs) {
    // 					if (applicationFilterConfig != null) {
    // 						System.out.println("Filter Name: " + applicationFilterConfig.getFilterName() + " FilterClass: " + applicationFilterConfig.getFilterClass());
    // 						if (applicationFilterConfig.getFilterName().equals("springSecurityFilterChain")) {
    // 							try {
    // 								Method getFilter = applicationFilterConfig.getClass().getDeclaredMethod("getFilter");
    // 								getFilter.setAccessible(true);
    // 								DelegatingFilterProxy delegatingFilterProxy = (DelegatingFilterProxy) getFilter.invoke(applicationFilterConfig);

    // 								Field delegate = DelegatingFilterProxy.class.getDeclaredField("delegate");
    // 								delegate.setAccessible(true);
    // 								FilterChainProxy  filterChainProxy = (FilterChainProxy) delegate.get(delegatingFilterProxy);
    // 								if (filterChainProxy != null) {
    // 									List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
    // 									for (SecurityFilterChain securityFilterChain : filterChains) {
    // 										DefaultSecurityFilterChain defaultSecurityFilterChain = (DefaultSecurityFilterChain) securityFilterChain;
    // 										System.out.println("\t" + defaultSecurityFilterChain.getRequestMatcher());
    // 										List<Filter> securityFilters = securityFilterChain.getFilters();
    // 										for (Filter securityFilter : securityFilters) {
    // 											System.out.println("\t\t" + securityFilter);
    // 										}
    // 									}
    // 								}
    // 							} catch (NoSuchMethodException | InvocationTargetException e) {
    // 								System.out.println(e.getMessage());
    // 							}
    // 						}
    // 					}
    // 				}
    // 			} catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
    // 				System.out.println(e.getMessage());
    // 			}
    // 		}
    // 		// response.setStatus(HttpServletResponse.SC_OK);
    // 		filterChain.doFilter(request, response);
    // 	}
    // }

    // @Bean
    // public FilterRegistrationBean<DumpFilters> userFilter() {
    // 	FilterRegistrationBean<DumpFilters> registrationBean = new FilterRegistrationBean<>();
    // 	registrationBean.setFilter(new DumpFilters());
    // 	registrationBean.addUrlPatterns("/dumpfilters");
    // 	registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
    // 	return registrationBean;
    // }