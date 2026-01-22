import { RiDeleteBin3Line } from "react-icons/ri";
import { useDispatch } from "react-redux";
import {
  removeFromCart,
  updateCartItemQuantity,
} from "../../../redux/slice/cartSlice";

const CartContents = ({ cart, userId, guestId }) => {
  const dispatch = useDispatch();

  const handleToCart = (productId, delta, quantity, size, color) => {
    const newQuantity = quantity + delta;
    if (newQuantity >= 1) {
      dispatch(
        updateCartItemQuantity({
          productId,
          quantity: newQuantity,
          guestId,
          userId,
          size,
          color,
        })
      );
    }
  };

  const handleRemoveFromCart = (productId, size, color) => {
    dispatch(removeFromCart({ productId, userId, guestId, size, color }));
  };

  return (
    <div className="divide-y">
      {cart.products.map((product, index) => (
        <div
          key={index}
          className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 py-4"
        >
          {/* Product Info */}
          <div className="flex gap-4">
            <img
              src={product.image}
              alt={product.name}
              className="w-24 h-28 object-cover rounded-md shadow"
            />
            <div>
              <h3 className="text-lg font-semibold text-gray-800">
                {product.name}
              </h3>
              <p className="text-sm text-gray-500 mt-1">
                Size: {product.size} | Color: {product.color}
              </p>

              {/* Quantity Controls */}
              <div className="flex items-center mt-3">
                <button
                  onClick={() =>
                    handleToCart(
                      product.productId,
                      -1,
                      product.quantity,
                      product.size,
                      product.color
                    )
                  }
                  className="px-3 py-1 rounded-md border border-gray-300 text-lg font-semibold hover:bg-gray-100"
                >
                  −
                </button>
                <span className="mx-4 text-base font-medium">
                  {product.quantity}
                </span>
                <button
                  onClick={() =>
                    handleToCart(
                      product.productId,
                      1,
                      product.quantity,
                      product.size,
                      product.color
                    )
                  }
                  className="px-3 py-1 rounded-md border border-gray-300 text-lg font-semibold hover:bg-gray-100"
                >
                  +
                </button>
              </div>
            </div>
          </div>

          {/* Price & Remove */}
          <div className="flex flex-col items-end gap-2">
            <p className="text-lg font-medium text-gray-800">
              ₹{product.price.toLocaleString()}
            </p>
            <button
              onClick={() =>
                handleRemoveFromCart(
                  product.productId,
                  product.size,
                  product.color
                )
              }
              className="text-red-600 hover:text-red-700 transition"
            >
              <RiDeleteBin3Line className="h-6 w-6" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default CartContents;
