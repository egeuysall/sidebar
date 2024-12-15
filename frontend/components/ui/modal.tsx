import { Dialog, DialogPanel, DialogBackdrop } from "@headlessui/react";
import { Cross1Icon } from "@radix-ui/react-icons";
import Button from "@/components/ui/button";

export default function Modal({
  open = false,
  setOpen = () => {},
  children,
  onClose = () => {},
  title,
}: {
  open?: boolean;
  setOpen?: (open: boolean) => void;
  children?: React.ReactNode;
  onClose?: () => void;
  title?: string;
}) {
  const handleClose = () => {
    onClose();
    setOpen(false);
  };

  return (
    <Dialog 
      open={open} 
      onClose={handleClose} 
      className="relative z-50"
    >
      <DialogBackdrop 
        className="fixed inset-0 bg-black/40" 
        onClick={handleClose}
      />
      <div className="fixed inset-0 flex w-screen items-center justify-center p-4">
        <DialogPanel className="max-w-lg space-y-4 border border-stroke-weak bg-background p-8 rounded-md">
          {title ? (
            <div className="flex justify-between">
              <h3 className="text-lg text-typography-strong font-bold">
                {title}
              </h3>
              <Button
                handleClick={handleClose}
                className="hover:opacity-80 transition-effect"
                variant="unstyled"
              >
                <Cross1Icon />
              </Button>
            </div>
          ) : null}  {/* Changed from empty fragment to null */}
          {children}
        </DialogPanel>
      </div>
    </Dialog>
  );
}