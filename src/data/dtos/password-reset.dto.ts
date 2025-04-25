export interface IPasswordResetDto {
	password: string;
	passwordConfirm: string;
	token?: string;
}
