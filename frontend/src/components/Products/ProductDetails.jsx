import { useEffect, useState } from "react";
import { toast } from "sonner";
import ProductGrid from "./ProductGrid";
import { useParams } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import {
  fetchProductDetails,
  fetchSimilarProducts,
} from "../../../redux/slice/productsSlice";
import { addToCart } from "../../../redux/slice/cartSlice";

const ProductDetails = ({ productId }) => {
  const { id } = useParams();
  const dispatch = useDispatch();
  const { selectedProduct, loading, error, similarProducts } = useSelector(
    (state) => state.products
  );
  const { user, guestId } = useSelector((state) => state.auth);

  const [mainImage, setMainImage] = useState("");
  const [selectedSize, setSelectedSize] = useState("");
  const [selectedColor, setSelectedColor] = useState("");
  const [quantity, setQuantity] = useState(1);
  const [isButtonDisabled, setIsButtonDisabled] = useState(false);

  const productFetchId = productId || id;

  useEffect(() => {
    if (productFetchId) {
      dispatch(fetchProductDetails(productFetchId));
      dispatch(fetchSimilarProducts({ id: productFetchId }));
    }
  }, [dispatch, productFetchId]);

  useEffect(() => {
    if (selectedProduct?.images?.length > 0) {
      setMainImage(selectedProduct.images[0].url);
    }
  }, [selectedProduct]);

  const handleQuantityChange = (action) => {
    if (action === "plus") setQuantity((prev) => prev + 1);
    if (action === "minus" && quantity > 1) setQuantity((prev) => prev - 1);
  };

  const handleAddToCart = () => {
    if (!selectedColor || !selectedSize) {
      toast.error("Please select a size and color before adding to cart.", {
        duration: 1000,
      });
      return;
    }

    setIsButtonDisabled(true);

    dispatch(
      addToCart({
        productId: productFetchId,
        quantity,
        size: selectedSize,
        color: selectedColor,
        guestId,
        userId: user?._id,
      })
    )
      .then(() => {
        toast.success("Product added to the cart", {
          duration: 1000,
        });
      })
      .finally(() => setIsButtonDisabled(false));
  };
  if (loading) return <p className="text-center py-10">Loading...</p>;
  if (error) return <p className="text-center text-red-500">Error: {error}</p>;

  return (
    <div className="p-6">
      {selectedProduct && (
        <div className="max-w-6xl mx-auto bg-white p-8 rounded-lg">
          <div className="flex flex-col lg:flex-row gap-8">
            {/* Thumbnails (Desktop) */}
            <div className="hidden md:flex flex-col gap-4">
              {selectedProduct.images.map((img, idx) => (
                <img
                  key={idx}
                  src={img.url}
                  alt={img.altText || `Thumbnail ${idx}`}
                  className={`w-20 h-20 object-cover rounded-lg cursor-pointer border ${
                    mainImage === img.url ? "border-black" : "border-gray-300"
                  }`}
                  onClick={() => setMainImage(img.url)}
                />
              ))}
            </div>

            {/* Main Image */}
            <div className="md:w-1/2">
              <img
                src={mainImage}
                alt="Main Product"
                className="w-full max-h-[550px] object-cover rounded-lg"
              />
              {/* Thumbnails (Mobile) */}
              <div className="flex md:hidden gap-4 mt-4 overflow-x-auto">
                {selectedProduct.images.map((img, idx) => (
                  <img
                    key={idx}
                    src={img.url}
                    alt={img.altText || `Thumbnail ${idx}`}
                    className={`w-20 h-20 object-cover rounded-lg cursor-pointer border ${
                      mainImage === img.url ? "border-black" : "border-gray-300"
                    }`}
                    onClick={() => setMainImage(img.url)}
                  />
                ))}
              </div>
            </div>

            {/* Product Details */}
            <div className="md:w-1/2">
              <h1 className="text-3xl font-semibold mb-2">
                {selectedProduct.name}
              </h1>
              <p className="text-lg text-gray-400 line-through">
                {selectedProduct.originalPrice &&
                  `$${selectedProduct.originalPrice}`}
              </p>
              <p className="text-2xl text-gray-700 font-medium mb-4">
                ${selectedProduct.price}
              </p>
              <p className="text-gray-600 mb-6">{selectedProduct.description}</p>

              {/* Color */}
              <div className="mb-4">
                <p className="text-gray-800 font-medium">Color:</p>
                <div className="flex gap-2 mt-2">
                  {selectedProduct.colors.map((color) => (
                    <button
                      key={color}
                      onClick={() => setSelectedColor(color)}
                      className={`w-8 h-8 rounded-full border transition duration-200 ${
                        selectedColor === color
                          ? "border-4 border-black"
                          : "border-gray-300"
                      }`}
                      style={{
                        backgroundColor: color.toLowerCase(),
                        filter: "brightness(0.85)",
                      }}
                    ></button>
                  ))}
                </div>
              </div>

              {/* Size */}
              <div className="mb-4">
                <p className="text-gray-800 font-medium">Size:</p>
                <div className="flex gap-2 mt-2">
                  {selectedProduct.sizes.map((size) => (
                    <button
                      key={size}
                      onClick={() => setSelectedSize(size)}
                      className={`px-4 py-2 rounded border text-sm font-medium transition duration-200 ${
                        selectedSize === size
                          ? "bg-black text-white border-black"
                          : "text-gray-700 border-gray-300 hover:bg-gray-100"
                      }`}
                    >
                      {size}
                    </button>
                  ))}
                </div>
              </div>

              {/* Quantity */}
              <div className="mb-6">
                <p className="text-gray-800 font-medium">Quantity:</p>
                <div className="flex items-center gap-4 mt-2">
                  <button
                    onClick={() => handleQuantityChange("minus")}
                    className="px-3 py-1.5 bg-gray-200 rounded text-lg hover:bg-gray-300"
                  >
                    -
                  </button>
                  <span className="text-lg font-medium">{quantity}</span>
                  <button
                    onClick={() => handleQuantityChange("plus")}
                    className="px-3 py-1.5 bg-gray-200 rounded text-lg hover:bg-gray-300"
                  >
                    +
                  </button>
                </div>
              </div>

              {/* Add to Cart */}
              <button
                onClick={handleAddToCart}
                disabled={isButtonDisabled}
                className={`bg-black text-white py-3 px-6 rounded w-full text-center font-semibold transition duration-200 ${
                  isButtonDisabled
                    ? "cursor-not-allowed opacity-50"
                    : "hover:bg-gray-900"
                }`}
              >
                {isButtonDisabled ? "Adding..." : "ADD TO CART"}
              </button>

              {/* Characteristics */}
              <div className="mt-10 text-gray-800">
                <h3 className="text-xl font-semibold mb-4">Characteristics</h3>
                <table className="w-full text-left text-sm border-t pt-4">
                  <tbody>
                    <tr>
                      <td className="py-1 font-medium">Brand</td>
                      <td className="py-1">{selectedProduct.brand}</td>
                    </tr>
                    <tr>
                      <td className="py-1 font-medium">Material</td>
                      <td className="py-1">{selectedProduct.material}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Similar Products */}
          <div className="mt-20">
            <h2 className="text-2xl text-center font-semibold mb-6">
              You May Also Like
            </h2>
            <ProductGrid
              products={similarProducts}
              loading={loading}
              error={error}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default ProductDetails;
