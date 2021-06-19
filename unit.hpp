#ifndef unit_h__
#define unit_h__

#include "traits.hpp"

//单个tuple去索引
template <typename Tuple, typename F, std::size_t...Is>
void tuple_switch(const std::size_t i, Tuple&& t, F&& f, index_sequence<Is...>) {
	[](...) {}(
		(i == Is && (
			(void)std::forward<F>(f)(std::get<Is>(std::forward<Tuple>(t))), false))...
		);
}

template <typename Tuple, typename F>
void tuple_switch(const std::size_t i, Tuple&& t, F&& f) {
	static constexpr auto N =
		std::tuple_size <remove_reference_t<Tuple >>::value;

	tuple_switch(i, std::forward<Tuple>(t), std::forward<F>(f),
		make_index_sequence<N>{});
}

/**********使用例子********/

//auto const t = std::make_tuple(42, 'z', 3.14, 13, 0, "Hello, World!");

//for (std::size_t i = 0; i < std::tuple_size<decltype(t)>::value; ++i) {
//	wheel::unit::tuple_switch(i, t, [](const auto& v) {
//		std::cout << v << std::endl;
//		});


template<typename F, typename...Ts, std::size_t...Is>
void for_each_tuple_front(std::tuple<Ts...>&& tuple, F&& func,index_sequence<Is...>) {
	constexpr auto SIZE = std::tuple_size<traits::remove_reference_t<decltype(tuple)>>::value;
#if (_MSC_VER >= 1700 && _MSC_VER <= 1900) //vs2012-vs2015
	if (constexpr(SIZE > 0)) {
		using expander = int[];
		(void)expander {
			((void)std::forward<F>(func)(std::get<Is>(tuple), std::integral_constant<size_t, Is>{}), false)...
		};
	}
#else
	if constexpr (SIZE > 0) {
		using expander = int[];
		(void)expander {
			((void)std::forward<F>(func)(std::get<Is>(tuple), std::integral_constant<size_t, Is>{}), false)...
		};
	}
#endif // _MSC_VER <=1923

}

template<typename F, typename...Ts>
void for_each_tuple_front(std::tuple<Ts...>&& tuple, F&& func) {
	for_each_tuple_front(std::forward<std::tuple<Ts...>>(tuple), func, traits::make_index_sequence<sizeof...(Ts)>());
}

template<typename F, typename...Ts, std::size_t...Is>
void for_each_tuple_back(std::tuple<Ts...>&& tuple, F&& func,index_sequence<Is...>) {
	//匿名构造函数调用
	constexpr auto SIZE = std::tuple_size<traits::remove_reference_t<decltype(tuple)>>::value;
#if (_MSC_VER >= 1700 && _MSC_VER <= 1900) //vs2012-vs2015
	if (constexpr (SIZE > 0)) {
		[](...) {}(0,
			((void)std::forward<F>(func)(std::get<Is>(tuple), std::integral_constant<size_t, Is>{}), false)...
			);
	}
#else
	if constexpr (SIZE > 0) {
		[](...) {}(0,
			((void)std::forward<F>(func)(std::get<Is>(tuple), std::integral_constant<size_t, Is>{}), false)...
			);
	}
#endif // #ifdef _MSC_VER <=1900
}

template<typename F, typename...Ts>
void for_each_tuple_back(std::tuple<Ts...>&& tuple, F&& func) {
	for_each_tuple_back(std::forward<std::tuple<Ts...>>(tuple), func, traits::make_index_sequence<sizeof...(Ts)>());
}
	}
#endif // unit_h__
