"use client";

import React, { useCallback, useState } from "react";
import { useDropzone } from "react-dropzone";
import { Cross2Icon } from "@radix-ui/react-icons";
import { CloudUpload } from "lucide-react";
import Image from "next/image";
import Button from "./button";

interface FileWithPreview extends File {
  preview: string;
}

export default function AvatarUploader({
  handleChange,
  initialAvatar,
}: {
  handleChange: (file: FileWithPreview) => void;
  initialAvatar?: string;
}) {
  const [file, setFile] = useState<FileWithPreview | null>(null);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      const newFile = Object.assign(acceptedFiles[0], {
        preview: URL.createObjectURL(acceptedFiles[0]),
      });
      setFile(newFile);
      handleChange(newFile);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { "image/*": [] },
    maxFiles: 1,
  });

  const removeFile = () => {
    if (file) {
      URL.revokeObjectURL(file.preview);
    }
    setFile(null);
  };

  return (
    <div className="max-w-md">
      {file || initialAvatar ? (
        <div className="text-center flex flex-col gap-4" role="group" aria-label="Selected profile picture preview">
          <div {...getRootProps()} className="relative p-4 flex flex-col gap-2 items-center justify-center rounded-full w-36 h-36 transition-all duration-150 ease-in-out select-none cursor-pointer group">
            <input {...getInputProps()} aria-label="Choose profile picture file" />
            <Image
              src={file?.preview || initialAvatar || ""}
              alt="Profile picture preview"
              fill
              style={{ objectFit: "cover" }}
              className="rounded-full"
            />
            <div className="absolute inset-0 bg-black/0 group-hover:bg-black/60 rounded-full transition-all duration-150 flex items-center justify-center">
              <CloudUpload className="text-white opacity-0 group-hover:opacity-100 transition-opacity duration-150" width={24} height={24} aria-hidden="true" />
            </div>
          </div>
          {file && (
            <div className="flex flex-col gap-2 items-start">
              <Button
                handleClick={removeFile}
                className="text-error hover:opacity-90 transition-effect text-sm flex items-center gap-1"
                variant="unstyled"
                aria-label="Remove selected profile picture"
              >
                <Cross2Icon width={16} height={16} aria-hidden="true" />
                Remove
              </Button>
            </div>
          )}
        </div>
      ) : (
        <div
          {...getRootProps()}
          className={`p-4 flex flex-col gap-2 items-center justify-center rounded-full w-36 h-36 border-2 transition-all duration-150 ease-in-out select-none cursor-pointer ${
            isDragActive
              ? "bg-fill-hover border-stroke-weak"
              : "bg-fill border-stroke-weak hover:bg-fill-hover"
          }`}
          role="button"
          aria-label="Upload profile picture"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              e.currentTarget.click();
            }
          }}
        >
          <input {...getInputProps()} aria-label="Choose profile picture file" />
          <CloudUpload width={24} height={24} aria-hidden="true" />
          <p className="text-sm">
            {isDragActive ? "Drop image here" : "Upload image"}
          </p>
        </div>
      )}
    </div>
  );
}
