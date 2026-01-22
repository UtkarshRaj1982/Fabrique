import React, { useEffect } from "react";
import { useDispatch, useSelector } from "react-redux";
import { Link, useParams } from "react-router-dom";
import { fetchOrderDetails } from "../../redux/slice/orderSlice";

const OrderDetailsPage = () => {
  const { id } = useParams();
  const dispatch = useDispatch();
  const { orderDetails, loading, error } = useSelector((state) => state.orders);

  useEffect(() => {
    dispatch(fetchOrderDetails(id));
  }, [dispatch, id]);

  if (loading) return <p className="p-4">Loading...</p>;
  if (error) return <p className="p-4 text-red-500">Error: {error}</p>;

  return (
    <div className="max-w-7xl mx-auto p-4 sm:p-6 dark:text-white">
      <h2 className="text-2xl font-bold mb-6">Order Details</h2>

      {!orderDetails ? (
        <p>No Order details found.</p>
      ) : (
        <div className="p-4 sm:p-6 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow">
          {/* Order Header */}
          <div className="flex flex-col sm:flex-row justify-between mb-8">
            <div>
              <h3 className="text-lg sm:text-xl font-semibold">
                Order ID: #{orderDetails._id}
              </h3>
              <p className="text-gray-600 dark:text-gray-400">
                {new Date(orderDetails.createdAt).toLocaleDateString()}
              </p>
            </div>
            <div className="flex flex-col items-start sm:items-end gap-2 mt-4 sm:mt-0">
              {/* Corrected isPaid badge */}
              <span
                className={`${
                  orderDetails.isPaid
                    ? "bg-green-100 text-green-700 dark:bg-green-800 dark:text-green-200"
                    : "bg-red-100 text-red-700 dark:bg-red-800 dark:text-red-200"
                } px-3 py-1 rounded-full text-sm font-medium`}
              >
                {orderDetails.isPaid ? "Paid" : "Pending Payment"}
              </span>

              <span
                className={`${
                  orderDetails.isDelivered
                    ? "bg-green-100 text-green-700 dark:bg-green-800 dark:text-green-200"
                    : "bg-yellow-100 text-yellow-700 dark:bg-yellow-700 dark:text-white"
                } px-3 py-1 rounded-full text-sm font-medium`}
              >
                {orderDetails.isDelivered ? "Delivered" : "Pending Delivery"}
              </span>
            </div>
          </div>

          {/*Customer payment and shipping info */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-8 mb-8">
            <div>
              <h4 className="text-lg font-semibold mb-2">Payment Info</h4>
              <p>Method: {orderDetails.paymentMethod}</p>
              <p>Status: {orderDetails.isPaid ? "Paid" : "Unpaid"}</p>
            </div>
            <div>
              <h4 className="text-lg font-semibold mb-2">Shipping Info</h4>
              <p>Method: {orderDetails.shippingMethod || "Standard"}</p>
              <p>
                Address:{" "}
                {`${orderDetails.shippingAddress.city}, ${orderDetails.shippingAddress.country}`}
              </p>
            </div>
            <div>
              <h4 className="text-lg font-semibold mb-2">Total</h4>
              <p>₹{orderDetails.totalPrice?.toFixed(2) || "0.00"}</p>
            </div>
          </div>

          {/* Product Table */}
          <div className="overflow-x-auto">
            <h4 className="text-lg font-semibold mb-4">Products</h4>
            <table className="min-w-full text-sm text-gray-600 dark:text-gray-300">
              <thead className="bg-gray-100 dark:bg-gray-700 text-xs uppercase">
                <tr>
                  <th className="py-2 px-4 text-left">Name</th>
                  <th className="py-2 px-4 text-left">Unit Price</th>
                  <th className="py-2 px-4 text-left">Qty</th>
                  <th className="py-2 px-4 text-left">Total</th>
                </tr>
              </thead>
              <tbody>
                {orderDetails.orderItems?.map((item, idx) => (
                  <tr key={`${item.productId}-${idx}`} className="border-b dark:border-gray-700">
                    <td className="py-2 px-4 flex items-center gap-3">
                      <img
                        src={item.image}
                        alt={item.name}
                        className="w-12 h-12 object-cover rounded-md"
                      />
                      <Link
                        to={`/product/${item.productId}`}
                        className="text-blue-600 dark:text-blue-400 hover:underline"
                      >
                        {item.name}
                      </Link>
                    </td>
                    <td className="py-2 px-4">₹{item.price.toFixed(2)}</td>
                    <td className="py-2 px-4">{item.quantity}</td>
                    <td className="py-2 px-4">
                      ₹{(item.price * item.quantity).toFixed(2)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-6">
            <Link to="/my-orders" className="text-blue-600 hover:underline dark:text-blue-400">
              ← Back to My Orders
            </Link>
          </div>
        </div>
      )}
    </div>
  );
};

export default OrderDetailsPage;
