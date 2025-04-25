// @ts-check

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
	eslint.configs.recommended,
	...tseslint.configs.recommendedTypeChecked,
	{
		ignores: ["**/node_modules/**", "**/dist/**"],
	},
	{
		rules: {
			"no-console": "error",
			"no-unused-vars": "off",
			"@typescript-eslint/no-unused-vars": "error",
			"@typescript-eslint/ban-types": "error",
		},
	},
	{
		languageOptions: {
			parserOptions: {
				project: true,
				tsconfigRootDir: import.meta.dirname,
			},
		},
	},
);
