import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate, useParams } from "react-router-dom";
import { fetchProductDetails } from "../../../redux/slice/productsSlice";
import axios from "axios";
import { updateProduct } from "../../../redux/slice/adminProductSlice";

export const EditProductPage = () => {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { id } = useParams();
  const { selectedProduct, loading, error } = useSelector(
    (state) => state.products
  );

  const [productData, setProductData] = useState({
    name: "",
    description: "",
    price: 0,
    countInStock: 0,
    sku: "",
    category: "",
    brand: "",
    sizes: [],
    colors: [],
    collections: "",
    material: "",
    gender: "",
    images: [],
  });

  const [uploading, setUploading] = useState(false);

  useEffect(() => {
    if (id) {
      dispatch(fetchProductDetails(id));
    }
  }, [dispatch, id]);

  useEffect(() => {
    if (selectedProduct) {
      setProductData(selectedProduct);
    }
  }, [selectedProduct]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setProductData((prevData) => ({ ...prevData, [name]: value }));
  };

  const handleImageUpload = async (e) => {
    const file = e.target.files[0];
    const formData = new FormData();
    formData.append("image", file);

    try {
      setUploading(true);
      const { data } = await axios.post(
        `${import.meta.env.VITE_BACKEND_URL}/api/upload`,
        formData,
        {
          headers: { "Content-Type": "multipart/form-data" },
        }
      );
      setProductData((prevData) => ({
        ...prevData,
        images: [...prevData.images, { url: data.imageUrl, altText: "" }],
      }));
      setUploading(false);
    } catch (error) {
      console.error(error);
      setUploading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    dispatch(updateProduct({ id, productData }));
    navigate("/admin/products");
  };

  if (loading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;

  return (
    <div className="max-w-5xl mx-auto p-6 bg-white shadow-lg rounded-lg">
      <h2 className="text-3xl font-bold text-gray-800 mb-8">Edit Product</h2>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Form Field Generator */}
        {[
          { label: "Product Name", name: "name", type: "text" },
          { label: "Price", name: "price", type: "number" },
          { label: "Count In Stock", name: "countInStock", type: "number" },
          { label: "SKU", name: "sku", type: "text" },
          { label: "Category", name: "category", type: "text" },
          { label: "Brand", name: "brand", type: "text" },
          { label: "Collections", name: "collections", type: "text" },
          { label: "Material", name: "material", type: "text" },
          { label: "Gender", name: "gender", type: "text" },
        ].map(({ label, name, type }) => (
          <div key={name}>
            <label className="block font-medium mb-1 text-gray-700">
              {label}
            </label>
            <input
              type={type}
              name={name}
              value={productData[name]}
              onChange={handleChange}
              className="w-full border border-gray-300 rounded-md p-2 focus:ring-2 focus:ring-green-400 focus:outline-none"
              required={name === "name"}
            />
          </div>
        ))}

        {/* Description */}
        <div>
          <label className="block font-medium mb-1 text-gray-700">
            Description
          </label>
          <textarea
            name="description"
            value={productData.description}
            onChange={handleChange}
            className="w-full border border-gray-300 rounded-md p-2 focus:ring-2 focus:ring-green-400 focus:outline-none"
            rows={4}
            required
          />
        </div>

        {/* Sizes */}
        <div>
          <label className="block font-medium mb-1 text-gray-700">
            Sizes (comma-separated)
          </label>
          <input
            type="text"
            name="sizes"
            value={productData.sizes.join(", ")}
            onChange={(e) =>
              setProductData({
                ...productData,
                sizes: e.target.value.split(",").map((s) => s.trim()),
              })
            }
            className="w-full border border-gray-300 rounded-md p-2 focus:ring-2 focus:ring-green-400 focus:outline-none"
          />
        </div>

        {/* Colors */}
        <div>
          <label className="block font-medium mb-1 text-gray-700">
            Colors (comma-separated)
          </label>
          <input
            type="text"
            name="colors"
            value={productData.colors.join(", ")}
            onChange={(e) =>
              setProductData({
                ...productData,
                colors: e.target.value.split(",").map((c) => c.trim()),
              })
            }
            className="w-full border border-gray-300 rounded-md p-2 focus:ring-2 focus:ring-green-400 focus:outline-none"
          />
        </div>

        {/* Image Upload */}
        <div>
          <label className="block font-medium mb-2 text-gray-700">
            Upload Image
          </label>
          <input type="file" onChange={handleImageUpload} />
          {uploading && <p className="text-sm text-gray-500 mt-1">Uploading image...</p>}
          <div className="flex flex-wrap gap-4 mt-4">
            {productData.images.map((image, index) => (
              <div key={index}>
                <img
                  src={image.url}
                  alt={image.altText || "Product"}
                  className="w-24 h-24 object-cover rounded-md shadow"
                />
              </div>
            ))}
          </div>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          className="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 rounded-md transition-colors duration-200"
        >
          Update Product
        </button>
      </form>
    </div>
  );
};
