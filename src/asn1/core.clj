(ns asn1.core
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [clojure.pprint :refer [pprint]])
  (:import bitHelper.Bytes
           java.nio.ByteBuffer
           javax.xml.bind.DatatypeConverter
           (java.nio BufferUnderflowException)
           (clojure.lang Ref)))

(defn base64-extract
  [path]
  (reduce str "" (remove #(str/starts-with? % "----") (line-seq (io/reader path)))))

(defn base64-bytes
  [path]
  (let [b64-str ^String (base64-extract path)]
    (DatatypeConverter/parseBase64Binary b64-str)))

(defn base64-buffer
  [path]
  (ByteBuffer/wrap (base64-bytes path)))

(defn to-hex-str
  [^Byte b]
  (format "%02x" b))

(def base64-buffer-ref
  (some-> "test_rsa" io/resource base64-buffer ref))

(defn read-bytes
  [^Ref buff n]
  (dosync
    (let [buff'  @buff
          pos    (.position buff')
          retval (make-array Byte/TYPE (+ pos n))]
      (try (.get buff' retval pos n)
           (alter buff #(.position % (+ pos n)))
           (drop pos retval)
           (catch BufferUnderflowException bue
             (binding [*out* *err*]
               (println "The buffer contains less than " n " elements") (println bue)))
           (catch IndexOutOfBoundsException ioobe
             (binding [*out* *err*]
               (println "Wrong index range to read from the buffer: " pos "-" n) (println ioobe)))
           (catch Exception e
             (binding [*out* *err*]
               (println "Something happened (cit.):") (println e)))))))

(defn read-byte [buff] (first (read-bytes buff 1)))         ;for grammatical correctness sake

(defn buff-empty?
  [^Ref buff]
  (let [buff' @buff]
    (>= (.position buff') (.limit buff'))))

(defn parse-tag
  [^Byte b]
  (let [tag-class        (Bytes/unsignedShiftRight b 6)
        tag-type         (bit-and b 2r00111111)
        tag-class-parsed (case tag-class
                           2r00 :universal
                           nil)]
    (if tag-class-parsed
      (case tag-type
        2r00000001 :boolean
        2r00000010 :integer
        2r00000011 :bit-string
        2r00000100 :octet-string
        2r00000101 :null
        2r00000110 :object-identifier
        2r00001100 :utf8-string
        2r00010011 :printable-string
        2r00010100 :teletex-string
        2r00011110 :bmp-string
        2r00110000 :sequence
        2r00110001 :set
        nil
        ))))

(defn assemble-bytes
  [bytes]
  (if (<= (count bytes) 1)
    (bit-and (first bytes) 0x00FF)
    (apply bit-or
           (map-indexed #(let [t (bit-and (int %2) 0xFF)]
                           (if (zero? %1) t
                                          (bit-shift-left t (* %1 8))))
                        (reverse bytes)))))

(defn read-tlv
  [buff]
  (if-not (buff-empty? buff)
    (let [tag       (some-> buff read-byte parse-tag)

          ;length requires multiple steps
          next-byte (read-byte buff)
          length    (let [short-or-long? (Bytes/unsignedShiftRight next-byte 7)
                          lval           (Bytes/and next-byte 2r01111111)]
                      (if (= short-or-long? 2r0)
                        lval
                        (some-> buff (read-bytes lval) assemble-bytes)))

          val       (some-> buff (read-bytes length))
          value     (case tag
                      :integer (apply str (for [v val] (to-hex-str v)))
                      :sequence (ByteBuffer/wrap (into-array Byte/TYPE val))
                      ::not-supported)]                     ;because no other type can be found
      {:tag tag :length length :value value})))             ;in the test data set

(defn parse-asn1
  [buff]
  (loop [buff'  (ref buff)
         retval []]
    (if-not (buff-empty? buff')
      (recur buff' (conj retval (let [{:keys [value] :as tlv} (read-tlv buff')]
                                  (if (isa? (type value) ByteBuffer)
                                    (update tlv :value parse-asn1)
                                    tlv))))
      retval)))

(defn -main [& args]
  (if-let [key-path (first args)]
    (pprint (parse-asn1 (base64-buffer key-path)))
    (binding [*out* *err*]
      (println "no path given")
      (System/exit 1))))

(comment

  (some-> "/home/vandr0iy/.ssh/XXXX_rsa"
          base64-buffer
          parse-asn1)

  (some-> "test_rsa"
          io/resource
          base64-buffer
          parse-asn1
          )

  (defn print-binary
    [^Byte b]
    (some-> b
            (bit-and 0xff)
            (Integer/toBinaryString)
            (#(format "%8s" %))
            (str/replace " " "0")))

  (some->> "/home/vandr0iy/.ssh/test_rsa"
           base64-bytes
           b64-buffer-pprint
           ;(#(format "%02x" %))
           )
  (some-> "/home/vandr0iy/.ssh/test_rsa"
          base64-buffer
          (.get (make-array Byte/TYPE 3) 0 3)
          ;read-length-short
          ;:long
          ;read-tag
          ;(bit-and 0xff)
          ; Integer/toBinaryString
          ;type

          ;print-binary
          ;(#(format "%02x" %))

          ;(bit-shift-right 5)
          ;(Byte/toUnsignedInt)

          )



  (some-> 0x82
          (unsigned-bit-shift-right 6)
          (= 2r10)
          ;print-binary
          ;(#(format "%02x" %))

          ;(Shift/unsignedRight 6)
          ;(Shift/left 6)

          ;print-binary

          )

  (defn b64-buffer-pprint
    [#^bytes bs]
    (do (doall (map-indexed
                 #(do (print (format "%02x" %2) " ")
                      (if (= 15 (mod %1 16))
                        (println)))
                 bs)) nil))


  (Integer/toBinaryString 130)
  (Integer/toBinaryString (byte -126))

  (print-binary (bit-shift-right 128 5))
  (format "%02x" (Shift/unsignedRight 0x82 6))

  (into [] (read-bytes base64-buffer-ref 3))
  @base64-buffer-ref
  (buff-empty? base64-buffer-ref)
  (repeatedly 2 #(if-not (buff-empty? base64-buffer-ref)
                   (read-tlv base64-buffer-ref)))

  (:length arst)
  (let [[hi lo] (:length arst)]
    (println
      (format "%02x" hi)
      (format "%02x" lo)
      (format (assemble-bytes (:length arst)))
      ))

  )