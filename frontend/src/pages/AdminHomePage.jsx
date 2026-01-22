import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link } from "react-router-dom";
import { fetchAdminProducts } from "../../redux/slice/adminProductSlice";
import { fetchAllOrders } from "../../redux/slice/adminOrderSlice";

const AdminHomePage = () => {
  const dispatch = useDispatch();

  const {
    products,
    loading: productsLoading,
    error: productsError,
  } = useSelector((state) => state.adminProducts);

  const {
    orders,
    totalOrders,
    totalSales,
    loading: ordersLoading,
    error: ordersError,
  } = useSelector((state) => state.adminOrders);

  useEffect(() => {
    dispatch(fetchAdminProducts());
    dispatch(fetchAllOrders());
  }, [dispatch]);

  return (
    <div className="max-w-7xl mx-auto p-6">
      <h1 className="text-3xl font-bold mb-8 text-gray-800">Admin Dashboard</h1>

      {productsLoading || ordersLoading ? (
        <p className="text-center text-gray-600">Loading ...</p>
      ) : productsError ? (
        <p className="text-red-500">Error fetching products: {productsError}</p>
      ) : ordersError ? (
        <p className="text-red-500">Error fetching orders: {ordersError}</p>
      ) : (
        <>
          {/* Dashboard Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
            <div className="p-6 shadow-lg rounded-lg bg-white">
              <h2 className="text-lg font-medium text-gray-600">Revenue</h2>
              <p className="text-3xl font-bold text-green-600 mt-2">
                ${totalSales.toFixed(2)}
              </p>
            </div>
            <div className="p-6 shadow-lg rounded-lg bg-white">
              <h2 className="text-lg font-medium text-gray-600">Total Orders</h2>
              <p className="text-3xl font-bold text-blue-600 mt-2">
                {totalOrders}
              </p>
              <Link
                to="/admin/orders"
                className="text-sm text-blue-500 mt-2 inline-block hover:underline"
              >
                Manage Orders →
              </Link>
            </div>
            <div className="p-6 shadow-lg rounded-lg bg-white">
              <h2 className="text-lg font-medium text-gray-600">Total Products</h2>
              <p className="text-3xl font-bold text-purple-600 mt-2">
                {products.length}
              </p>
              <Link
                to="/admin/products"
                className="text-sm text-blue-500 mt-2 inline-block hover:underline"
              >
                Manage Products →
              </Link>
            </div>
          </div>

          {/* Recent Orders Table */}
          <div>
            <h2 className="text-2xl font-semibold text-gray-800 mb-4">
              Recent Orders
            </h2>
            <div className="overflow-x-auto rounded-lg shadow">
              <table className="min-w-full text-sm text-left text-gray-700 bg-white">
                <thead className="bg-gray-100 uppercase text-xs font-semibold">
                  <tr>
                    <th className="py-3 px-5">Order ID</th>
                    <th className="py-3 px-5">User</th>
                    <th className="py-3 px-5">Total Price</th>
                    <th className="py-3 px-5">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {orders.length > 0 ? (
                    orders.map((order) => (
                      <tr
                        key={order._id}
                        className="border-t hover:bg-gray-50 transition-colors"
                      >
                        <td className="py-3 px-5">{order._id}</td>
                        <td className="py-3 px-5">{order.user.name}</td>
                        <td className="py-3 px-5">${order.totalPrice.toFixed(2)}</td>
                        <td
                          className={`py-3 px-5 font-medium ${
                            order.status === "Delivered"
                              ? "text-green-600"
                              : order.status === "Pending"
                              ? "text-yellow-600"
                              : "text-gray-700"
                          }`}
                        >
                          {order.status}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td
                        colSpan={4}
                        className="py-4 text-center text-gray-500 italic"
                      >
                        No recent orders found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default AdminHomePage;
