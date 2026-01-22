import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { fetchUserOrders } from "../../redux/slice/orderSlice";

const MyOrderPage = () => {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { orders, loading, error } = useSelector((state) => state.orders);

  useEffect(() => {
    dispatch(fetchUserOrders());
  }, [dispatch]);

  const handleRowClick = (orderId) => {
    navigate(`/order/${orderId}`);
  };

  if (loading) return <p className="p-4 text-center">Loading...</p>;
  if (error) return <p className="p-4 text-center text-red-500">Error: {error}</p>;

  return (
    <div className="max-w-7xl mx-auto p-4 sm:p-6">
      <h2 className="text-xl sm:text-2xl font-bold mb-6 text-gray-800 dark:text-white">My Orders</h2>
      <div className="relative shadow-md sm:rounded-lg overflow-x-auto bg-white dark:bg-gray-800 border dark:border-gray-700">
        <table className="min-w-full text-sm text-left text-gray-500 dark:text-gray-300">
          <thead className="bg-gray-100 dark:bg-gray-700 text-xs uppercase text-gray-700 dark:text-gray-200">
            <tr>
              <th className="py-3 px-4">Image</th>
              <th className="py-3 px-4">Order ID</th>
              <th className="py-3 px-4">Created</th>
              <th className="py-3 px-4">Shipping Address</th>
              <th className="py-3 px-4">Items</th>
              <th className="py-3 px-4">Price</th>
              <th className="py-3 px-4">Status</th>
            </tr>
          </thead>
          <tbody>
            {orders.length > 0 ? (
              orders.map((order) => (
                <tr
                  key={order._id}
                  onClick={() => handleRowClick(order._id)}
                  className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
                >
                  <td className="py-3 px-4">
                    <img
                      src={order.orderItems[0]?.image}
                      alt={order.orderItems[0]?.name}
                      className="w-12 h-12 object-cover rounded-lg"
                    />
                  </td>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-white whitespace-nowrap">
                    #{order._id}
                  </td>
                  <td className="py-3 px-4">
                    <div className="text-xs sm:text-sm">
                      {new Date(order.createdAt).toLocaleDateString()}<br />
                      {new Date(order.createdAt).toLocaleTimeString()}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    {order.shippingAddress
                      ? `${order.shippingAddress.city}, ${order.shippingAddress.country}`
                      : "N/A"}
                  </td>
                  <td className="py-3 px-4">{order.orderItems.length}</td>
                  <td className="py-3 px-4">${order.totalPrice.toFixed(2)}</td>
                  <td className="py-3 px-4">
                    <span
                      className={`${
                        order.isPaid
                          ? "bg-green-100 text-green-700 dark:bg-green-800 dark:text-green-100"
                          : "bg-red-100 text-red-700 dark:bg-red-800 dark:text-red-100"
                      } px-3 py-1 rounded-full text-xs font-medium`}
                    >
                      {order.isPaid ? "Paid" : "Pending"}
                    </span>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td
                  colSpan={7}
                  className="py-6 px-4 text-center text-gray-500 dark:text-gray-400"
                >
                  You have no orders.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default MyOrderPage;
