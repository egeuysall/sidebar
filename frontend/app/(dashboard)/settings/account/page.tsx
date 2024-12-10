"use client";

import Input from "@/components/ui/input";
import SettingsBox from "@/components/ui/settings-box";
import { useState, useEffect } from "react";
import axios from "axios";
import { User } from "@/types";
import Spinner from "@/components/ui/spinner";
import {
  resendUpdateEmailConfirmation,
  updateUser,
  updateUserEmail,
  uploadAvatar,
} from "./actions";
import Button from "@/components/ui/button";
import toast from "@/lib/toast";
import Image from "next/image";

const apiUrl = process.env.NEXT_PUBLIC_API_URL;

export default function AccountSettingsPage() {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [avatar, setAvatar] = useState<File | undefined>(undefined);

  const [userValues, setUserValues] = useState<{
    firstName?: { initial: string; current: string };
    lastName?: { initial: string; current: string };
    email?: { initial: string; current: string };
    updatedEmail?: string;
  }>({});

  async function getUser() {
    const user = await axios
      .get(`${apiUrl}/auth/identity`, {
        withCredentials: true,
      })
      .then((response) => {
        console.log(response.data);
        return response.data;
      })
      .catch((error) => console.error(error));

    setUser({
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      avatarUrl: user.avatar_url,
      isAdmin: user.is_admin,
    });

    setUserValues({
      firstName: { initial: user.first_name, current: user.first_name },
      lastName: { initial: user.last_name, current: user.last_name },
      email: { initial: user.email, current: user.email },
      updatedEmail: user.updated_email,
    });
  }

  useEffect(() => {
    setIsLoading(true);
    getUser().then(() => {
      setIsLoading(false);
    });
  }, []);

  if (isLoading) return <Spinner />;

  return (
    <>
      {/* <div>
				<span>Email initial: {userValues.email?.initial}</span>
				<span>Email current: {userValues.email?.current}</span>
				<span>Updated email: {userValues.updatedEmail}</span>
			</div> */}
      <SettingsBox
        title="Your Name"
        description="This will be your display name in the dashboard."
        note="Max 32 characters"
        onSettingSubmit={async () => {
          await updateUser({
            user,
            firstName: userValues.firstName?.current,
            lastName: userValues.lastName?.current,
          });

          setUserValues({
            ...userValues,
            firstName: {
              initial: userValues.firstName?.current || "",
              current: userValues.firstName?.current || "",
            },
            lastName: {
              initial: userValues.lastName?.current || "",
              current: userValues.lastName?.current || "",
            },
          });

          toast({
            message: "Profile updated",
            mode: "success",
          });
        }}
        disabled={
          userValues.firstName?.initial === userValues.firstName?.current &&
          userValues.lastName?.initial === userValues.lastName?.current
        }
      >
        <div className="flex gap-4">
          <Input
            type="text"
            placeholder="First Name"
            value={userValues.firstName?.current}
            handleChange={(e) =>
              setUserValues({
                ...userValues,
                firstName: {
                  initial: userValues.firstName?.initial || "",
                  current: e.target.value,
                },
              })
            }
          />
          <Input
            type="text"
            placeholder="Last Name"
            value={userValues.lastName?.current}
            handleChange={(e) =>
              setUserValues({
                ...userValues,
                lastName: {
                  initial: userValues.lastName?.initial || "",
                  current: e.target.value,
                },
              })
            }
          />
        </div>
      </SettingsBox>
      <SettingsBox
        title="Your Email"
        description="This will be the email you use to log in to your dashboard and receive notifications."
        onSettingSubmit={async () =>
          await updateUserEmail({
            user,
            email: userValues.email?.current || "",
          }).then((res) => {
            if (res.error) {
              setUserValues({
                ...userValues,
                email: {
                  initial: userValues.email?.initial || "",
                  current: userValues.email?.initial || "",
                },
              });

              if (res.code == "email_taken") {
                toast({
                  message: "Email is already taken",
                  mode: "error",
                });
              } else {
                toast({
                  message: "Something went wrong",
                  mode: "error",
                });
              }
            } else {
              setUserValues({
                ...userValues,
                updatedEmail: res?.updated_email || "",
                email: {
                  initial: res?.email || "",
                  current: res?.email || "",
                },
              });

              toast({
                message: "Email updated",
                description: "Please check your email for a confirmation link.",
                mode: "success",
              });
            }
          })
        }
        note={
          userValues.updatedEmail &&
          userValues.email?.initial !== userValues.updatedEmail ? (
            <span className="text-sm">
              To update your email, click the confirmation link we sent to{" "}
              <strong>{userValues.updatedEmail}</strong>.{" "}
              <Button
                className="underline"
                variant="link"
                handleClick={() =>
                  resendUpdateEmailConfirmation({ user }).then(() => {
                    toast({
                      message: "Email sent",
                      description:
                        "Please check your email for a confirmation link.",
                      mode: "success",
                    });
                  })
                }
              >
                Resend
              </Button>
            </span>
          ) : (
            "You will need to confirm your email if you change it."
          )
        }
        disabled={
          userValues.email?.initial === userValues.email?.current ||
          userValues.email?.current === userValues.updatedEmail
        }
      >
        <Input
          type="email"
          placeholder="Email"
          value={userValues.email?.current}
          handleChange={(e) =>
            setUserValues({
              ...userValues,
              email: {
                initial: userValues.email?.initial || "",
                current: e.target.value,
              },
            })
          }
        />
      </SettingsBox>
      <SettingsBox
        title="Your Avatar"
        description="This is your avatar in the dashboard."
        onSettingSubmit={async () => {
          const formData = new FormData();
          formData.append("avatar", avatar || "");
          await uploadAvatar({ user, formData })
            .then(() => {
              toast({
                message: "Avatar updated",
                mode: "success",
              });
            })
            .catch((error) => {
              console.error(error);
              toast({
                message: "Error updating avatar",
                mode: "error",
              });
            });
        }}
        disabled={!avatar}
        note="Square image recommended. Accepted file types: .png, .jpg. Max file size: 2MB."
      >
        <Image
          src={avatar ? URL.createObjectURL(avatar) : user?.avatarUrl || ""}
          alt="Avatar"
          width={100}
          height={100}
          className="rounded-full object-cover aspect-square"
        />
        <Input
          type="file"
          placeholder="Avatar"
          handleChange={(e) =>
            setAvatar((e.target as HTMLInputElement).files?.[0])
          }
        />
      </SettingsBox>
    </>
  );
}
