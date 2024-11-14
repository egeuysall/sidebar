export type ApiError = {
	message: string;
	error: string;
};

export type User = {
	id: string;
	firstName: string;
	lastName: string;
	email: string;
	isAdmin: boolean;
	avatarUrl: string;
};
