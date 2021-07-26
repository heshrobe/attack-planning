#|
(defcomputer Sysclient0501 windows-computer
  :ip-address-string "142.20.57.246"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  ) 

(defcomputer Sysclient0811 windows-computer
  :ip-address-string "142.20.59.44"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  )

(defcomputer Sysclient0010  windows-computer
  :ip-address-string "142.20.56.11"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  )

(defcomputer Sysclient0069  windows-computer
  :ip-address-string "142.20.56.70"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  )

(defcomputer Sysclient0203 windows-computer
  :ip-address-string "142.20.56.204"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  )

(defcomputer Sysclient0358 windows-computer
  :ip-address-string "142.20.57.103"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  )

(defcomputer Sysclient0618 windows-computer
  :ip-address-string "142.20.58.107"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  )

(defcomputer Sysclient0851 windows-computer
  :ip-address-string "142.20.59.84"
  :typical nil
  :authorization-pool systemia-domain-controller-pool
  :superuser ()
  )

|#

#|

;;; We know about 2 specific users because they got phished
;;; but it would probably be cheating to include them specifically

(defuser bantonio@systemia.com
    :user-type user
    :machines (Sysclient0501)
    :typical nil
    :capabilities (user-write)
    :authorization-pools (systemia-domain-controller-pool)
    )

(defuser rsantilli@systemia.com
    :user-type user
    :machines (Sysclient0811)
    :typical nil
    :capabilities (user-write)
    :authorization-pools (systemia-domain-controller-pool)
    )


|#