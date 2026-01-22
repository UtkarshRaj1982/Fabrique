import { Link } from "react-router-dom";

const ProductGrid = ({ products, loading, error }) => {
  if (loading) return <p className="text-center py-10">Loading...</p>;
  if (error) return <p className="text-center text-red-500">Error: {error}</p>;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
      {products.map((product) => (
        <Link
          key={product._id}
          to={`/product/${product._id}`}
          className="block transition-transform hover:scale-[1.015]"
        >
          <div className="bg-white p-4 rounded-lg shadow hover:shadow-md transition duration-200 h-full flex flex-col">
            <div className="w-full h-80 mb-4 overflow-hidden rounded-lg">
              <img
                src={product.images[0]?.url}
                alt={product.images[0]?.altText || product.name}
                className="w-full h-full object-cover transition-transform duration-300 hover:scale-105"
              />
            </div>
            <div className="flex-grow flex flex-col justify-between">
              <h3 className="text-base font-medium text-gray-800 mb-1 line-clamp-2">
                {product.name}
              </h3>
              <p className="text-gray-600 font-semibold text-sm">
                ${product.price}
              </p>
            </div>
          </div>
        </Link>
      ))}
    </div>
  );
};

export default ProductGrid;
